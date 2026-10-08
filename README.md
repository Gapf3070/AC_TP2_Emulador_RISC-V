# TP2 - Emulador RISC-V Simplificado

**Disciplina:** Arquitetura de Computadores (ICC062) - 2026/2
**Professor:** Juan Gabriel Colonna
**Monitor:** Pedro Lucas Bezerra Mendes
**Aluno:** Gabriel Almeida de Paula Fonseca
**Matrícula:** 22450084

---

## Descrição

Este repositório contém a implementação de um emulador simplificado para o conjunto de instruções de 32 bits do RISC-V em Python3. O emulador interpreta diretamente arquivos de código assembly (`.s`), mantendo o estado interno dos registradores, da memória e do Program Counter (`pc`).

---

## Como Executar

O emulador utiliza apenas bibliotecas nativas do Python3 e não necessita de nenhuma instalação adicional.

### Comando Básico:
```bash
python3 emulador.py codigo.s