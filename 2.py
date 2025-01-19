import hashlib
import itertools
import time
import concurrent.futures

def calculate_hash(hash_type, password):
    if hash_type == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif hash_type == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    else:
        raise ValueError("Unsupported hash type")

def brute_force(hash_type, target_hash, alphabet, length):
    for combination in itertools.product(alphabet, repeat=length):
        password = ''.join(combination)
        if calculate_hash(hash_type, password) == target_hash:
            return password
    return None

def brute_force_multithreaded(hash_type, target_hash, alphabet, length, num_threads):
    def worker(start, step):
        for i in range(start, len(alphabet) ** length, step):
            combination = number_to_combination(i, alphabet, length)
            password = ''.join(combination)
            if calculate_hash(hash_type, password) == target_hash:
                return password
        return None

    def number_to_combination(number, alphabet, length):
        result = []
        for _ in range(length):
            result.append(alphabet[number % len(alphabet)])
            number //= len(alphabet)
        return result[::-1]

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, start, num_threads) for start in range(num_threads)]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                executor.shutdown(wait=False)
                return result
    return None

def main():
    hashes = [
        "1115dd800feaacefdf481f1f9070374a2a81e27880f187396db67958b207cbad",
        "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
        "74e1bb62f8dabb8125a58852b63bdf6eaef667cb56ac7f7cdba6d7305c50a22f",
        "7a68f09bd992671bb3b19a5e70b7827e"
    ]
    hash_types = ["sha256", "sha256", "sha256", "md5"]
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    length = 5

    mode = input("Выберите режим (1 - однопоточный, 2 - многопоточный): ")
    if mode == '2':
        num_threads = int(input("Введите количество потоков: "))

    for i, target_hash in enumerate(hashes):
        print(f"\nИщем пароль для хэша: {target_hash}")
        start_time = time.time()

        if mode == '1':
            password = brute_force(hash_types[i], target_hash, alphabet, length)
        elif mode == '2':
            password = brute_force_multithreaded(hash_types[i], target_hash, alphabet, length, num_threads)
        else:
            print("Неверный выбор режима.")
            return

        elapsed_time = time.time() - start_time

        if password:
            print(f"Найденный пароль: {password}")
        else:
            print("Пароль не найден.")
        print(f"Затраченное время: {elapsed_time:.2f} секунд")

if __name__ == "__main__":
    main()
