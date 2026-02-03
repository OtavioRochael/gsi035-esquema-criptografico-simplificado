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

def GEN(seed: list[int]) -> list[int]:
    # Tamanho da seed
    n = len(seed)
    # Tamanho da chave final
    k = []
    
    # Calcula um hash simples da seed para usar como diferenciador
    # Isso quebra a simetria entre seeds complementares
    seed_hash = 0
    for i, bit in enumerate(seed):
        seed_hash = (seed_hash * 31 + bit * (i + 1)) % 256
    
    # Estado interno para mistura - incorpora posição
    state = []
    for i in range(n):
        # Cada bit é misturado com sua posição e o hash da seed
        state.append(seed[i] ^ ((seed_hash >> (i % 8)) & 1))
    
    for rodada in range(4):
        bloco = []
        for i in range(n):
            # Combina múltiplos elementos do estado com operações não-lineares
            idx1 = i
            idx2 = (i + rodada + 1) % n
            idx3 = (i * 2 + rodada) % n
            idx4 = (i + seed_hash) % n  # Índice dependente do hash
            
            # Operação não-linear: majoritária + XOR com índice
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
        # Isso garante que cada rodada produza bits diferentes
        novo_state = []
        for i in range(n):
            # Mistura o estado atual com o bloco gerado e seed original
            feedback = state[i] ^ bloco[(i + rodada) % n] ^ seed[(i + rodada) % n]
            novo_state.append(feedback)
        state = novo_state
    
    return k