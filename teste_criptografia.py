import time
import random
from gen import GEN
from enc import ENC
from dec import DEC


def contar_bits_diferentes(a: list[int], b: list[int]) -> int:
    """Conta quantos bits são diferentes entre duas listas."""
    return sum(1 for i in range(len(a)) if a[i] != b[i])


def teste_basico():
    """Testa se DEC(K, ENC(K, M)) == M."""
    print("=" * 60)
    print("TESTE BÁSICO: Criptografia e Descriptografia")
    print("=" * 60)
    
    # Seed de exemplo
    seed = [1, 0, 1, 1, 0, 0, 1, 0]
    
    # Gera a chave
    K = GEN(seed)
    print(f"Seed ({len(seed)} bits): {seed}")
    print(f"Chave K ({len(K)} bits): {K}")
    
    # Mensagem de exemplo (mesmo tamanho que K)
    M = [0, 1, 0, 1, 1, 0, 0, 1] * 4  # 32 bits
    print(f"Mensagem M ({len(M)} bits): {M}")
    
    # Criptografa
    C = ENC(K, M)
    print(f"Cifra C ({len(C)} bits): {C}")
    
    # Descriptografa
    M_recuperada = DEC(K, C)
    print(f"M recuperada ({len(M_recuperada)} bits): {M_recuperada}")
    
    # Verifica
    if M == M_recuperada:
        print("✓ SUCESSO: M == DEC(K, ENC(K, M))")
        return True
    else:
        print("✗ FALHA: Mensagem não foi recuperada corretamente!")
        return False


def teste_difusao():
    """
    Teste de Difusão: Altera 1 bit da mensagem e mede quantos bits
    da cifra são alterados.
    """
    print("\n" + "=" * 60)
    print("TESTE DE DIFUSÃO")
    print("Alterando 1 bit da mensagem, quantos bits da cifra mudam?")
    print("=" * 60)
    
    seed = [1, 0, 1, 1, 0, 0, 1, 0]
    K = GEN(seed)
    n = len(K)
    
    total_testes = 100
    total_bits_alterados = 0
    
    for _ in range(total_testes):
        # Mensagem aleatória
        M = [random.randint(0, 1) for _ in range(n)]
        C1 = ENC(K, M)
        
        # Altera um bit aleatório
        pos = random.randint(0, n - 1)
        M_alterada = M.copy()
        M_alterada[pos] = 1 - M_alterada[pos]
        C2 = ENC(K, M_alterada)
        
        # Conta bits diferentes
        bits_alterados = contar_bits_diferentes(C1, C2)
        total_bits_alterados += bits_alterados
    
    media = total_bits_alterados / total_testes
    percentual = (media / n) * 100
    
    print(f"Tamanho da cifra: {n} bits")
    print(f"Testes realizados: {total_testes}")
    print(f"Média de bits alterados: {media:.2f}")
    print(f"Percentual médio: {percentual:.2f}%")
    print(f"Ideal (efeito avalanche): ~50%")
    
    if percentual > 40:
        print("✓ BOA DIFUSÃO!")
    else:
        print("⚠ Difusão pode ser melhorada")
    
    return media, percentual


def teste_confusao():
    """
    Teste de Confusão: Altera 1 bit da seed e mede quantos bits
    da cifra são alterados (mantendo M fixo).
    """
    print("\n" + "=" * 60)
    print("TESTE DE CONFUSÃO")
    print("Alterando 1 bit da seed, quantos bits da cifra mudam?")
    print("=" * 60)
    
    seed_size = 8
    total_testes = 100
    total_bits_alterados = 0
    
    for _ in range(total_testes):
        # Seed aleatória
        seed = [random.randint(0, 1) for _ in range(seed_size)]
        K1 = GEN(seed)
        n = len(K1)
        
        # Mensagem fixa aleatória
        M = [random.randint(0, 1) for _ in range(n)]
        C1 = ENC(K1, M)
        
        # Altera um bit da seed
        pos = random.randint(0, seed_size - 1)
        seed_alterada = seed.copy()
        seed_alterada[pos] = 1 - seed_alterada[pos]
        K2 = GEN(seed_alterada)
        C2 = ENC(K2, M)
        
        # Conta bits diferentes
        bits_alterados = contar_bits_diferentes(C1, C2)
        total_bits_alterados += bits_alterados
    
    media = total_bits_alterados / total_testes
    n = seed_size * 4  # Tamanho da chave
    percentual = (media / n) * 100
    
    print(f"Tamanho da seed: {seed_size} bits")
    print(f"Tamanho da cifra: {n} bits")
    print(f"Testes realizados: {total_testes}")
    print(f"Média de bits alterados: {media:.2f}")
    print(f"Percentual médio: {percentual:.2f}%")
    print(f"Ideal (efeito avalanche): ~50%")
    
    if percentual > 40:
        print("✓ BOA CONFUSÃO!")
    else:
        print("⚠ Confusão pode ser melhorada")
    
    return media, percentual


def teste_chaves_equivalentes():
    """
    Testa se existem chaves equivalentes (K1 != K2 mas ENC(M, K1) == ENC(M, K2)).
    """
    print("\n" + "=" * 60)
    print("TESTE DE CHAVES EQUIVALENTES")
    print("Verificando se seeds diferentes geram cifras iguais")
    print("=" * 60)
    
    seed_size = 8
    num_seeds = 256  # Testar todas as seeds de 8 bits seria 2^8 = 256
    
    # Gera chaves para várias seeds
    chaves = {}
    for i in range(num_seeds):
        seed = [(i >> j) & 1 for j in range(seed_size)]
        K = GEN(seed)
        chave_tupla = tuple(K)
        if chave_tupla in chaves:
            chaves[chave_tupla].append(seed)
        else:
            chaves[chave_tupla] = [seed]
    
    # Conta chaves únicas e equivalentes
    chaves_unicas = len(chaves)
    seeds_com_chaves_iguais = sum(1 for seeds in chaves.values() if len(seeds) > 1)
    
    print(f"Seeds testadas: {num_seeds}")
    print(f"Chaves únicas geradas: {chaves_unicas}")
    print(f"Seeds com chaves equivalentes: {seeds_com_chaves_iguais}")
    
    if seeds_com_chaves_iguais == 0:
        print("✓ SEM CHAVES EQUIVALENTES!")
    else:
        print(f"⚠ Encontradas {seeds_com_chaves_iguais} seeds com chaves equivalentes")
        # Mostra exemplos
        for k, seeds in chaves.items():
            if len(seeds) > 1:
                print(f"  Chave compartilhada por: {seeds[:3]}...")
                break
    
    return chaves_unicas, num_seeds


def teste_tempo_execucao():
    """Mede o tempo de execução das operações."""
    print("\n" + "=" * 60)
    print("TESTE DE TEMPO DE EXECUÇÃO")
    print("=" * 60)
    
    seed_size = 8
    num_operacoes = 10000
    
    # Prepara dados
    seed = [random.randint(0, 1) for _ in range(seed_size)]
    
    # Tempo GEN
    inicio = time.perf_counter()
    for _ in range(num_operacoes):
        K = GEN(seed)
    tempo_gen = time.perf_counter() - inicio
    
    # Prepara mensagem
    M = [random.randint(0, 1) for _ in range(len(K))]
    
    # Tempo ENC
    inicio = time.perf_counter()
    for _ in range(num_operacoes):
        C = ENC(K, M)
    tempo_enc = time.perf_counter() - inicio
    
    # Tempo DEC
    inicio = time.perf_counter()
    for _ in range(num_operacoes):
        M_dec = DEC(K, C)
    tempo_dec = time.perf_counter() - inicio
    
    print(f"Operações: {num_operacoes}")
    print(f"Tamanho seed: {seed_size} bits")
    print(f"Tamanho chave/mensagem: {len(K)} bits")
    print()
    print(f"Tempo GEN: {tempo_gen*1000:.2f} ms ({tempo_gen/num_operacoes*1e6:.2f} µs/op)")
    print(f"Tempo ENC: {tempo_enc*1000:.2f} ms ({tempo_enc/num_operacoes*1e6:.2f} µs/op)")
    print(f"Tempo DEC: {tempo_dec*1000:.2f} ms ({tempo_dec/num_operacoes*1e6:.2f} µs/op)")
    
    return tempo_gen, tempo_enc, tempo_dec


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("   TESTES DO ESQUEMA CRIPTOGRÁFICO SIMPLIFICADO")
    print("=" * 60)
    
    # Executa todos os testes
    teste_basico()
    teste_difusao()
    teste_confusao()
    teste_chaves_equivalentes()
    teste_tempo_execucao()
    
    print("\n" + "=" * 60)
    print("   TESTES CONCLUÍDOS")
    print("=" * 60)
