"""
Módulo principal que centraliza as operações do esquema criptográfico.

Expõe as funções principais:
- gen: Geração de chave a partir de uma seed
- enc: Criptografia de mensagem
- dec: Descriptografia de cifra
"""

from gen import GEN
from enc import ENC
from dec import DEC


def gen(seed: list[int]) -> list[int]:
    """
    Gera uma chave binária K com tamanho 4 * len(seed).
    
    Args:
        seed: Lista binária (0's e 1's) representando a semente.
        
    Returns:
        Lista binária K com tamanho 4 * len(seed).
    """
    return GEN(seed)


def enc(K: list[int], M: list[int]) -> list[int]:
    """
    Criptografa a mensagem M usando a chave K.
    
    Args:
        K: Chave binária (lista de 0's e 1's) com tamanho 4 * len(seed).
        M: Mensagem binária (lista de 0's e 1's) com mesmo tamanho de K.
        
    Returns:
        Cifra C como lista binária de mesmo tamanho.
    """
    return ENC(K, M)


def dec(K: list[int], C: list[int]) -> list[int]:
    """
    Descriptografa a cifra C usando a chave K.
    
    Args:
        K: Chave binária (lista de 0's e 1's) com tamanho 4 * len(seed).
        C: Cifra binária (lista de 0's e 1's) com mesmo tamanho de K.
        
    Returns:
        Mensagem original M como lista binária.
    """
    return DEC(K, C)


if __name__ == "__main__":
    # Exemplo de uso
    seed = [1, 0, 1, 1, 0, 0, 1, 0]
    mensagem = [0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
                0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1]
    
    print("=== Esquema Criptográfico Simplificado ===\n")
    
    # Geração de chave
    chave = gen(seed)
    print(f"Seed: {seed}")
    print(f"Chave gerada (tamanho {len(chave)}): {chave}\n")
    
    # Criptografia
    cifra = enc(chave, mensagem)
    print(f"Mensagem original: {mensagem}")
    print(f"Cifra: {cifra}\n")
    
    # Descriptografia
    mensagem_recuperada = dec(chave, cifra)
    print(f"Mensagem recuperada: {mensagem_recuperada}")
    print(f"Recuperação correta: {mensagem == mensagem_recuperada}")
