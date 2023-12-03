import random
from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.adapters.abenc_adapt_hybrid import HybridABEnc
import pickle
import time
import re

# In each of the 0-encoding and 1-encoding sets, E0
# a and E1
# b , the binary strings are arranged in the
# decreasing order of string length (i.e., the number of digits of a binary sequence)


def encode_number(x):
    # Convert the integer to a binary string
    binary_string = bin(x)[2:]

    # Pad the binary string with leading zeros if needed
    # standardize all binary strings to be of length 32
    binary_string = binary_string.zfill(32)
    # Initialize 0-encoding and 1-encoding sets
    S0_x = set()
    S1_x = set()

    # Iterate over the binary string and populate the sets
    for i in range(len(binary_string)):
        prefix = binary_string[:i+1]
        if prefix[-1] == '0':
            # Flip the least significant bit when adding to S0_x
            S0_x.add(prefix[:-1] + '1')
        else:
            S1_x.add(prefix)
    # convert the binary to decimal
    # sort S0_x and S1_x by length of the binary string
    S0_x = sorted(S0_x, key=lambda x: len(x), reverse=True)
    S1_x = sorted(S1_x, key=lambda x: len(x), reverse=True)
    return S0_x, S1_x

def modify_not_equal_conditions(access_policy):
    pattern = re.compile(r'(\w+)\s*(!=)\s*(\d+)')
    matches = pattern.findall(access_policy)
    for match in matches:
        identifier, operator, number = match
        S0_x, S1_x = encode_number(int(number))
        new_condition = f'({identifier} < {number} OR {identifier} > {number})'
        access_policy = access_policy.replace(
            f'{identifier} {operator} {number}', new_condition)
    return access_policy
def modify_access_policy(access_policy):
    access_policy = modify_not_equal_conditions(access_policy)
    pattern = re.compile(r'(\w+)\s*([<>])\s*(\d+)')
    matches = pattern.findall(access_policy)
    for match in matches:
        identifier, operator, number = match
        access_policy = access_policy.replace(
            f'{identifier} {operator} {number}', f'({identifier} {operator} {number})')
    matches = pattern.findall(access_policy)
    for match in matches:
        identifier, operator, number = match
        S0_x, S1_x = encode_number(int(number))
        if operator == '<':
            new_condition = ' OR '.join(f'{identifier}{"!!"}{x}' for x in S1_x)
        elif operator == '>':  # operator == '>'
            new_condition = ' OR '.join(f'{identifier}{"@@"}{x}' for x in S0_x)
        access_policy = access_policy.replace(
            f'({identifier} {operator} {number})', f'({new_condition})')
    pattern = re.compile(r'(\w+) = (\w+)')
    modified_policy = access_policy
    for match in pattern.findall(access_policy):
        old_expression = f'{match[0]} = {match[1]}'
        new_expression = f'({match[0]}$${match[1]})'
        new_expressionx = new_expression.upper()
        modified_policy = modified_policy.replace(
            old_expression, new_expressionx)
    return modified_policy


def process_attributes(attributes):
    pattern = re.compile(r'(\w+) = (\d+)')
    for i, attribute in enumerate(attributes):
        match = pattern.match(attribute)
        if match:
            attr_name = match.group(1).upper()
            attr_value = int(match.group(2))
            S0_attr, S1_attr = encode_number(attr_value)
            attr_encodings = [f'{attr_name}!!{x}' for x in S0_attr] + \
                [f'{attr_name}@@{x}' for x in S1_attr]
            attributes[i:i+1] = attr_encodings
    pattern = re.compile(r'(\w+) = (\w+)')
    for i, attribute in enumerate(attributes):
        match = pattern.match(attribute)
        if match:
            old_expression = attribute
            # capitalize the new_expression
            new_expression = f'{match[1]}$${match[2]}'
            new_expressionx = new_expression.upper()
            attributes[i] = new_expressionx
    return attributes


def generate_random_attribute(index):
    # Extend the list of attributes up to 'twenty'
    attributes = ['one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten',
                  'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen', 'sixteen', 'seventeen',
                  'eighteen', 'nineteen', 'twenty', 'twentyone', 'twentytwo', 'twentythree',
                  'twentyfour', 'twentyfive', 'twentysix', 'twentyseven', 'twentyeight', 'twentynine',
                  'thirty', 'thirtyone', 'thirtytwo', 'thirtythree', 'thirtyfour', 'thirtyfive',
                  'thirtysix', 'thirtyseven', 'thirtyeight', 'thirtynine', 'forty', 'fortyone',
                  'fortytwo', 'fortythree', 'fortyfour', 'fortyfive', 'fortysix', 'fortyseven',
                  'fortyeight', 'fortynine', 'fifty']
    return attributes[index]


def modify_access_policyx(access_policy, num_attributes):
    # Split the original access policy string into individual attributes
    attributes = access_policy.split()

    # Create a list to store the modified attributes
    modified_attributes = []
    for i in range(num_attributes):
        # Generate a random attribute and append it to the list
        modified_attributes.append(generate_random_attribute(i))

        # Randomly choose between AND and OR and append it to the list
        if random.choice([True, False]):
            conjunction = 'and'
        else:
            conjunction = 'or'
        modified_attributes.append(conjunction)

    # Remove the last AND or OR if present
    if modified_attributes and (modified_attributes[-1] == 'and' or modified_attributes[-1] == 'or'):
        modified_attributes.pop()

    # Join the modified attributes into a new access policy string
    new_access_policy = ' '.join(modified_attributes)
    new_access_policy = f"({new_access_policy})"

    return new_access_policy


def generate_attributes(benchmark_access_policy, extra_size):
    # Extract attributes from benchmark_access_policy
    # attributes = re.findall(r'\b\w+\b', benchmark_access_policy)
    attributes = re.findall(r'\b(?:(?!and|or)\w)+\b', benchmark_access_policy)

    # Generate extra attributes
    for i in range(extra_size):
        ne = generate_random_attribute(i).upper()
        attributes.append(ne)
    newAtt = []
    for elem in attributes:
        newAtt.append(elem.upper())
    return newAtt


def test(access_policy_len, extra_attribute_lenght, rangeNum1, rangeNum2):
    start_time = time.time()
    groupObj = PairingGroup('SS512')
    cpabe = CPabe_BSW07(groupObj)
    hyb_abe = HybridABEnc(cpabe, groupObj)
    (pk, mk) = hyb_abe.setup()
    access_policy = '((four and three) and (two or one) and (ran != 120) and (age < 25 and age > 10))'
    # access_policy = f'(age < {rangeNum2}  and age > {rangeNum1})'
    # print("RANGE BEING USED IN ACCESS_POLICY", rangeNum1, rangeNum2)
    # print("ACCESS POLICY LENGTH : ", access_policy_len,
        #   " ATTRIBUTE POLICY LENGHT : ", extra_attribute_lenght)
    new_access_policy = modify_access_policy(access_policy)
    # benchmark_access_policy = modify_access_policyx(
        # new_access_policy, access_policy_len)
    # print(benchmark_access_policy)
    # print(modify_access_policyx(access_policy), "ok")
    attributes = ['ONE', 'TWO', 'THREE','Prof',
                  'FOUR', 'ran = 121', 'age = 24', 'collegeTeacher = XYZ']
    # attributes = [f'age = {(rangeNum1+rangeNum2)//2}']
    # print(attributes,access_policy)
    # attributes = generate_attributes(
        # benchmark_access_policy, extra_attribute_lenght)
    processed_attributes = process_attributes(attributes)
    # print(len(processed_attributes),len(benchmark_access_policy),benchmark_access_policy)
    print(processed_attributes, "X")
    print(new_access_policy,'new Access policy')
    # print(processed_attributes,'new processedd attributes')
    sk = hyb_abe.keygen(pk, mk, processed_attributes)
    # print(len(attributes), "len")
    keygen_time = time.time() - start_time
    print("Keygen time: ", keygen_time*1e6, " microseconds")
    sourcefile = open("source.txt", 'rb')
    plaintext = sourcefile.read()
    sourcefile.close()

    encryptedfile = open("encrypted.txt", 'wb')
    ciphertext = hyb_abe.encrypt(pk, plaintext, new_access_policy)
    # ciphertext = hyb_abe.encrypt(pk, plaintext, benchmark_access_policy)
    encryption_time = time.time() - start_time
    print("Encryption time: ", encryption_time*1e6, " microseconds")
    ciphertext["c1"]["C"] = groupObj.serialize(ciphertext["c1"]["C"])
    for key in ciphertext["c1"]["Cy"]:
        ciphertext["c1"]["Cy"][key] = groupObj.serialize(
            ciphertext["c1"]["Cy"][key])
    ciphertext["c1"]["C_tilde"] = groupObj.serialize(
        ciphertext["c1"]["C_tilde"])
    for key in ciphertext["c1"]["Cyp"]:
        ciphertext["c1"]["Cyp"][key] = groupObj.serialize(
            ciphertext["c1"]["Cyp"][key])
    pickle.dump(ciphertext, encryptedfile)
    encryptedfile.close()

    encryptedfile = open("encrypted.txt", 'rb')
    ciphertext2 = pickle.load(encryptedfile)
    ciphertext2["c1"]["C"] = groupObj.deserialize(ciphertext2["c1"]["C"])
    for key in ciphertext2["c1"]["Cy"]:
        ciphertext2["c1"]["Cy"][key] = groupObj.deserialize(
            ciphertext2["c1"]["Cy"][key])
    ciphertext2["c1"]["C_tilde"] = groupObj.deserialize(
        ciphertext2["c1"]["C_tilde"])
    for key in ciphertext2["c1"]["Cyp"]:
        ciphertext2["c1"]["Cyp"][key] = groupObj.deserialize(
            ciphertext2["c1"]["Cyp"][key])
    try :
        print(hyb_abe.decrypt(pk, sk, ciphertext2), plaintext)
        ans = hyb_abe.decrypt(pk, sk, ciphertext2)
    except :    
        return
    decryption_time = time.time() - start_time
    print("Decryption time: ", decryption_time*1e6, " microseconds")
    encryptedfile.close()


if __name__ == "__main__":
    debug = True
    # for i in range(1,42):
        # test(i,0,0,0)
        # print('*'*30)
    # for i in range(1, 100000,50):
        # if 1e5-i > i:
            # test(1, i, i, 100000-i)
            # print('*'*30)
    # for i in range(1, 35):
        # test(15, i, 23, 23)
        # print('*'*30)
    test(0,0,0,0)
