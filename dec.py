# S-Box inversa para substituição reversa
S_BOX = [0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
         0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7]

# Calcula S-Box inversa automaticamente
S_BOX_INV = [0] * 16
for i in range(16):
    S_BOX_INV[S_BOX[i]] = i


def _bits_para_int(bits: list[int]) -> int:
    """Converte lista de bits para inteiro."""
    resultado = 0
    for bit in bits:
        resultado = (resultado << 1) | bit
    return resultado


def _int_para_bits(valor: int, tamanho: int) -> list[int]:
    """Converte inteiro para lista de bits com tamanho fixo."""
    bits = []
    for _ in range(tamanho):
        bits.append(valor & 1)
        valor >>= 1
    return bits[::-1]


def _substituicao_inversa(bloco: list[int]) -> list[int]:
    """Aplica S-Box inversa em blocos de 4 bits."""
    resultado = []
    for i in range(0, len(bloco), 4):
        nibble = bloco[i:i+4]
        if len(nibble) == 4:
            idx = _bits_para_int(nibble)
            substituido = S_BOX_INV[idx]
            resultado.extend(_int_para_bits(substituido, 4))
        else:
            resultado.extend(nibble)
    return resultado


def _permutacao_inversa(bloco: list[int]) -> list[int]:
    """Permutação inversa de bits."""
    n = len(bloco)
    resultado = [0] * n
    for i in range(n):
        # Posição original após permutação: nova_pos = (i * 5 + 3) % n
        # Precisamos encontrar i dado nova_pos
        nova_pos = (i * 5 + 3) % n
        resultado[i] = bloco[nova_pos]
    return resultado


def _xor_listas(a: list[int], b: list[int]) -> list[int]:
    """XOR entre duas listas de bits."""
    return [a[i] ^ b[i] for i in range(len(a))]


def _gerar_subchaves(K: list[int], num_rodadas: int) -> list[list[int]]:
    """Gera subchaves para cada rodada a partir da chave principal."""
    n = len(K)
    subchaves = []
    for r in range(num_rodadas):
        deslocamento = (r * 3) % n
        subchave = K[deslocamento:] + K[:deslocamento]
        constante = [(r >> i) & 1 for i in range(n)]
        subchave = _xor_listas(subchave, constante[:n])
        subchaves.append(subchave)
    return subchaves


def DEC(K: list[int], C: list[int]) -> list[int]:
    """
    Descriptografa a cifra C usando a chave K.
    
    Implementa o inverso da rede de substituição-permutação (SPN):
    - Aplica as operações inversas na ordem reversa
    - Usa S-Box inversa e permutação inversa
    
    Args:
        K: Chave binária (lista de 0's e 1's) com tamanho 4 * len(seed).
        C: Cifra binária (lista de 0's e 1's) com mesmo tamanho de K.
        
    Returns:
        Mensagem original M como lista binária.
    """
    NUM_RODADAS = 4
    
    # Gera as mesmas subchaves usadas na criptografia
    subchaves = _gerar_subchaves(K, NUM_RODADAS + 1)
    
    # Estado inicial é a cifra
    estado = C.copy()
    
    # Rodadas inversas (ordem reversa)
    for r in range(NUM_RODADAS - 1, -1, -1):
        # 1. Remove mistura com subchave (XOR é auto-inverso)
        estado = _xor_listas(estado, subchaves[r + 1])
        
        # 2. Permutação inversa
        estado = _permutacao_inversa(estado)
        
        # 3. Substituição inversa
        estado = _substituicao_inversa(estado)
    
    # Remove whitening inicial
    estado = _xor_listas(estado, subchaves[0])
    
    return estado