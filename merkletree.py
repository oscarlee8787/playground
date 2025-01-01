import hashlib
from pymerkle import InmemoryTree
from pymerkle import verify_inclusion

def hash_row(row_values):
    """Hash a row by concatenating its column values."""
    concatenated = ''.join(map(str, row_values))
    return hashlib.sha256(concatenated.encode()).digest()

# Step 1: Create hashed rows for Dataset A and Dataset B
dataset_a = [["Alice", 25], ["Bob", 30], ["Charlie", ]]
dataset_b = [["Alice", 25], ["Bob", 30], ["Charlie", ]]

print("\nDataset A Hashing:")
hashed_a = []
for row in dataset_a:
    h = hash_row(row)
    # print(f"Row {row} -> Original hash: {h.hex()}")
    hashed_a.append(h)

print("\nDataset B Hashing:")
hashed_b = []
for row in dataset_b:
    h = hash_row(row)
    # print(f"Row {row} -> Original hash: {h.hex()}")
    hashed_b.append(h)

# Step 2: Build Merkle Trees using InmemoryTree
tree_a = InmemoryTree(algorithm="sha256")
tree_b = InmemoryTree(algorithm="sha256")

# Add hashes to trees
# print("\nAdding hashes to tree A:")
for i, hash_value in enumerate(hashed_a):
    # print(f"Before adding - Hash {i}: {hash_value.hex()}")
    tree_a.append_entry(hash_value)
    # print(f"After adding - Leaf {i+1}: {tree_a.get_leaf(i+1).hex()}")

# print("\nAdding hashes to tree B:")
for i, hash_value in enumerate(hashed_b):
    # print(f"Before adding - Hash {i}: {hash_value.hex()}")
    tree_b.append_entry(hash_value)
    # print(f"After adding - Leaf {i+1}: {tree_b.get_leaf(i+1).hex()}")

# Step 3: Compare Merkle Roots
root_a = tree_a.get_state()
root_b = tree_b.get_state()

if root_a == root_b:
    print("Datasets are identical for the selected columns and rows.")
else:
    print("Datasets differ.")

# Step 4: Verify specific shared rows
print("\n=== Verification Process ===")
specific_row = ["Charlie", ]
specific_hash = hash_row(specific_row)
# print(f"Specific row hash: {specific_hash.hex()}")

# Add the hash to a temporary tree to get the tree's version of the hash
temp_tree = InmemoryTree(algorithm="sha256")
temp_tree.append_entry(specific_hash)
tree_specific_hash = temp_tree.get_leaf(1)
# print(f"Tree-transformed hash: {tree_specific_hash.hex()}")

# print("\nTree A Contents:")
for i in range(tree_a.get_size()):
    leaf = tree_a.get_leaf(i + 1)
    # print(f"Leaf {i+1}: {leaf.hex()}")

# Check inclusion in Tree A
leaf_index = None
for i in range(tree_a.get_size()):
    current_leaf = tree_a.get_leaf(i + 1)
    # print(f"Comparing {tree_specific_hash.hex()} with {current_leaf.hex()}")
    if current_leaf == tree_specific_hash:
        leaf_index = i + 1
        break

if leaf_index is not None:
    print(f"\nFound match at leaf index: {leaf_index}")
    try:
        # Get the proof for the full tree
        proof = tree_a.prove_inclusion(leaf_index)
        
        # Get the base and root
        base = tree_a.get_leaf(leaf_index)
        root = tree_a.get_state()
        
        # print("\nVerification Components:")
        # print(f"1. Base hash: {base.hex()}")
        # print(f"2. Root hash: {root.hex()}")
        # print(f"3. Proof object:")
        # print(f"   - Type: {type(proof)}")
        # print(f"   - Path: {proof.path if hasattr(proof, 'path') else 'No path'}")
        # print(f"   - Size: {proof.size if hasattr(proof, 'size') else 'No size'}")
        
        # Try verification using proof's resolve method
        try:
            resolved_hash = proof.resolve()
            # print(f"\nResolution Results:")
            # print(f"1. Resolved hash: {resolved_hash.hex()}")
            # print(f"2. Expected root: {root.hex()}")
            # print(f"3. Match: {resolved_hash == root}")
            
            if resolved_hash == root:
                print(f"Row {specific_row} exists in Dataset A.")
            else:
                print(f"Row {specific_row} does not exist in Dataset A.")
                # print("\nDebug Hash Comparison:")
                # print(f"- Resolved: {resolved_hash.hex()}")
                # print(f"- Expected: {root.hex()}")
        except Exception as ve:
            print(f"Resolution failed with error: {ve}")
            import traceback
            traceback.print_exc()
            
    except Exception as e:
        print(f"Proof generation failed with error: {e}")
        import traceback
        traceback.print_exc()
else:
    print(f"\nNo matching leaf found for row {specific_row}")
