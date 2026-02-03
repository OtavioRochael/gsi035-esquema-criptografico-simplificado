# S-Box para substituição não-linear (4 bits -> 4 bits)
# Projetada para máxima não-linearidade
S_BOX = [0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
         0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7]


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


def _substituicao(bloco: list[int]) -> list[int]:
    """Aplica S-Box em blocos de 4 bits para confusão."""
    resultado = []
    for i in range(0, len(bloco), 4):
        nibble = bloco[i:i+4]
        if len(nibble) == 4:
            idx = _bits_para_int(nibble)
            substituido = S_BOX[idx]
            resultado.extend(_int_para_bits(substituido, 4))
        else:
            # Se sobrar bits que não formam 4, manter como está
            resultado.extend(nibble)
    return resultado


def _permutacao(bloco: list[int]) -> list[int]:
    """Permutação de bits para difusão."""
    n = len(bloco)
    resultado = [0] * n
    for i in range(n):
        # Permutação baseada em multiplicação modular
        nova_pos = (i * 5 + 3) % n
        resultado[nova_pos] = bloco[i]
    return resultado


def _xor_listas(a: list[int], b: list[int]) -> list[int]:
    """XOR entre duas listas de bits."""
    return [a[i] ^ b[i] for i in range(len(a))]


def _gerar_subchaves(K: list[int], num_rodadas: int) -> list[list[int]]:
    """Gera subchaves para cada rodada a partir da chave principal."""
    n = len(K)
    subchaves = []
    for r in range(num_rodadas):
        # Rotação circular da chave
        deslocamento = (r * 3) % n
        subchave = K[deslocamento:] + K[:deslocamento]
        # XOR com constante de rodada para diferenciação
        constante = [(r >> i) & 1 for i in range(n)]
        subchave = _xor_listas(subchave, constante[:n])
        subchaves.append(subchave)
    return subchaves


def ENC(K: list[int], M: list[int]) -> list[int]:
    """
    Criptografa a mensagem M usando a chave K.
    
    Implementa uma rede de substituição-permutação (SPN) com:
    - 4 rodadas de transformação
    - Substituição via S-Box (confusão)
    - Permutação de bits (difusão)
    - Mistura com subchaves derivadas
    
    Args:
        K: Chave binária (lista de 0's e 1's) com tamanho 4 * len(seed).
        M: Mensagem binária (lista de 0's e 1's) com mesmo tamanho de K.
        
    Returns:
        Cifra C como lista binária de mesmo tamanho.
    """
    NUM_RODADAS = 4
    
    # Gera subchaves para cada rodada
    subchaves = _gerar_subchaves(K, NUM_RODADAS + 1)
    
    # Estado inicial: XOR com primeira subchave (whitening)
    estado = _xor_listas(M, subchaves[0])
    
    # Rodadas de transformação
    for r in range(NUM_RODADAS):
        # 1. Substituição (Confusão)
        estado = _substituicao(estado)
        
        # 2. Permutação (Difusão)
        estado = _permutacao(estado)
        
        # 3. Mistura com subchave da rodada
        estado = _xor_listas(estado, subchaves[r + 1])
    
    return estado