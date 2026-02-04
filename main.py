"""
Módulo principal que centraliza as operações do esquema criptográfico.

Funções principais:
- gen: Geração de chave a partir de uma seed
- enc: Criptografia de mensagem
- dec: Descriptografia de cifra
"""

# =============================================================================
# S-Box para substituição não-linear (4 bits -> 4 bits)
# =============================================================================
S_BOX = [0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
         0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7]

# Calcula S-Box inversa automaticamente
S_BOX_INV = [0] * 16
for i in range(16):
    S_BOX_INV[S_BOX[i]] = i


# =============================================================================
# Funções auxiliares
# =============================================================================

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


# =============================================================================
# Funções de substituição e permutação para ENC
# =============================================================================

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
            resultado.extend(nibble)
    return resultado


def _permutacao(bloco: list[int]) -> list[int]:
    """Permutação de bits para difusão."""
    n = len(bloco)
    resultado = [0] * n
    for i in range(n):
        nova_pos = (i * 5 + 3) % n
        resultado[nova_pos] = bloco[i]
    return resultado


# =============================================================================
# Funções de substituição e permutação inversas para DEC
# =============================================================================

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
        nova_pos = (i * 5 + 3) % n
        resultado[i] = bloco[nova_pos]
    return resultado


# =============================================================================
# GEN - Geração de Chave
# =============================================================================

def gen(seed: list[int]) -> list[int]:
    """
    Gera uma chave binária K com tamanho 4 * len(seed).

    Utiliza uma técnica de expansão baseada em:
    - Rotações circulares
    - XOR com padrões derivados da seed
    - Mistura não-linear para evitar chaves equivalentes
    - Incorpora a posição absoluta de cada bit da seed

    Args:
        seed: Lista binária (0's e 1's) representando a semente.
        
    Returns:
        Lista binária K com tamanho 4 * len(seed).
    """
    n = len(seed)
    k = []
    
    # Calcula um hash simples da seed para usar como diferenciador
    seed_hash = 0
    for i, bit in enumerate(seed):
        seed_hash = (seed_hash * 31 + bit * (i + 1)) % 256
    
    # Estado interno para mistura - incorpora posição
    state = []
    for i in range(n):
        state.append(seed[i] ^ ((seed_hash >> (i % 8)) & 1))
    
    for rodada in range(4):
        bloco = []
        for i in range(n):
            idx1 = i
            idx2 = (i + rodada + 1) % n
            idx3 = (i * 2 + rodada) % n
            idx4 = (i + seed_hash) % n
            
            bit1 = state[idx1]
            bit2 = state[idx2]
            bit3 = state[idx3]
            bit4 = state[idx4]
            
            # Função majoritária estendida
            majoritario = (bit1 & bit2) | (bit2 & bit3) | (bit1 & bit3)
            
            # Adiciona não-linearidade com bit4
            nao_linear = (bit1 & bit4) ^ (bit2 | bit3)
            
            # XOR com padrão baseado na posição, rodada e hash
            padrao = ((i * (rodada + 1) + seed_hash) % 2)
            novo_bit = majoritario ^ padrao ^ nao_linear ^ seed[i % n]
            
            bloco.append(novo_bit)
        
        k.extend(bloco)
        
        # Atualiza o estado para a próxima rodada (feedback)
        novo_state = []
        for i in range(n):
            feedback = state[i] ^ bloco[(i + rodada) % n] ^ seed[(i + rodada) % n]
            novo_state.append(feedback)
        state = novo_state
    
    return k


# =============================================================================
# ENC - Criptografia
# =============================================================================

def enc(K: list[int], M: list[int]) -> list[int]:
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


# =============================================================================
# DEC - Descriptografia
# =============================================================================

def dec(K: list[int], C: list[int]) -> list[int]:
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


# =============================================================================
# Exemplo de uso
# =============================================================================

if __name__ == "__main__":
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
