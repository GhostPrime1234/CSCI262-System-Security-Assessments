import itertools
import numpy as np
import matplotlib.pyplot as plt


# Define the specific hash values to be used
def generate_distribution(num_sub_puzzles: int, k: int):
    hash_values = [i for i in range(1, 2 ** k + 1)]
    combinations = itertools.product(hash_values, repeat=num_sub_puzzles)
    distribution = {}
    for combo in combinations:
        hash_sum = sum(combo)
        if hash_sum in distribution:
            distribution[hash_sum] += 1
        else:
            distribution[hash_sum] = 1
    return distribution


def calculate_statistics(distribution):
    sums = list(distribution.keys())
    frequencies = list(distribution.values())
    total_cases = np.sum(frequencies)
    average = np.sum(m_sum * freq for m_sum, freq in zip(sums, frequencies)) / total_cases
    variance = np.sum(freq * (m_sum - average) ** 2 for m_sum, freq in zip(sums, frequencies)) / total_cases
    std_deviation = np.sqrt(variance)
    return average, variance, std_deviation


def plot_distribution(distribution: dict, puzzle_name: str, color: str):
    plt.figure(figsize=(10, 6))
    plt.bar(distribution.keys(), distribution.values(), color=color, alpha=0.7)
    plt.title(f"{puzzle_name} Distribution")
    plt.xlabel("Number of Hashes Needed")
    plt.ylabel("Number of Cases")
    keys = list(distribution.keys())
    plt.xticks(range(np.min(keys), np.max(keys) + 1), rotation=45)
    plt.show()


def main():
    # Parameters for Puzzle A
    num_sub_puzzles_a = 1
    k_a = 5

    # Parameters for Puzzle B
    num_sub_puzzles_b = 4
    k_b = 3

    # Generate distributions
    distribution_a = generate_distribution(num_sub_puzzles_a, k_a)
    distribution_b = generate_distribution(num_sub_puzzles_b, k_b)

    # Calculate statistics
    average_a, variance_a, std_dev_a = calculate_statistics(distribution_a)
    average_b, variance_b, std_dev_b = calculate_statistics(distribution_b)

    # Print results
    print("Puzzle A Distribution:")
    for hash_sum, frequency in distribution_a.items():
        print(f"Hashes needed: {hash_sum}, Cases: {frequency}")
    print(f"Average: {average_a}, Variance: {variance_a}, Standard Deviation: {std_dev_a}\n")

    print("Puzzle B Distribution:")
    for hash_sum, frequency in distribution_b.items():
        print(f"Hashes needed: {hash_sum}, Cases: {frequency}")
    print(f"Average: {average_b}, Variance: {variance_b}, Standard Deviation: {std_dev_b}")

    # Plot Puzzle A Distribution
    plot_distribution(distribution_a, puzzle_name="Puzzle A", color="blue")

    # Plot Puzzle B Distribution
    plot_distribution(distribution_b, puzzle_name="Puzzle B", color="red")


if __name__ == "__main__":
    main()
