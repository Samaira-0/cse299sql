# -*- coding: utf-8 -*-
import pandas as pd
import pickle
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
import sys
import os

# Handle Windows encoding issues
if sys.platform.startswith('win'):
    try:
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    except:
        pass  # Fallback to default encoding

def create_and_save_tokenizer():
    """
    Recreate the tokenizer from your training notebook and save it
    This matches your exact training configuration
    """
    
    # Load your training data (adjust path as needed)
    try:
        df = pd.read_csv('SQLiV4.csv', encoding='utf-8')  # Specify encoding
        print(f"[SUCCESS] Loaded dataset with {len(df)} samples")
        
        # Ensure the column name is correct
        if 'Sentence' not in df.columns:
            # Try common column names
            possible_columns = ['query', 'sql', 'text', 'input', 'statement', 'Query']
            for col in possible_columns:
                if col in df.columns:
                    df['Sentence'] = df[col]
                    print(f"[INFO] Using column '{col}' as 'Sentence'")
                    break
            else:
                # Use the first column if no match found
                df['Sentence'] = df.iloc[:, 0]
                print(f"[INFO] Using first column '{df.columns[0]}' as 'Sentence'")
                
    except FileNotFoundError:
        print("[WARNING] SQLiV4.csv not found. Creating tokenizer with comprehensive sample data...")
        
        # Create comprehensive sample data that matches your training patterns
        sample_data = [
            # Normal SQL queries
            "SELECT * FROM users WHERE id = 1",
            "SELECT name, email FROM customers WHERE active = 1",
            "INSERT INTO products (name, price) VALUES ('item', 10.99)",
            "UPDATE users SET last_login = NOW() WHERE id = 123",
            "DELETE FROM logs WHERE date < '2023-01-01'",
            "SELECT COUNT(*) FROM orders WHERE status = 'completed'",
            "SELECT u.name, p.title FROM users u JOIN posts p ON u.id = p.user_id",
            "CREATE TABLE temp_table (id INT, name VARCHAR(50))",
            "ALTER TABLE users ADD COLUMN phone VARCHAR(15)",
            "SELECT AVG(price) FROM products WHERE category = 'electronics'",
            
            # SQL Injection patterns - Basic
            "' OR '1'='1' --",
            "admin' OR '1'='1'#",
            "' OR 1=1--",
            "' OR 'a'='a",
            "' OR 1=1#",
            "') OR ('1'='1",
            "' OR '1'='1' /*",
            "' OR 1=1 LIMIT 1--",
            "' OR 1=1 ORDER BY 1--",
            "' OR 1=1 GROUP BY 1--",
            
            # Union-based attacks
            "1' UNION SELECT username, password FROM users--",
            "1' UNION ALL SELECT NULL,NULL,version()--",
            "1' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
            "' UNION SELECT NULL, username, password FROM users--",
            "1' UNION SELECT schema_name FROM information_schema.schemata--",
            "1' UNION SELECT table_name FROM information_schema.tables--",
            "1' UNION SELECT column_name FROM information_schema.columns--",
            
            # Stacked queries
            "'; DROP TABLE users; --",
            "1'; INSERT INTO users (username, password) VALUES ('hacker', 'password')--",
            "1'; UPDATE users SET password = 'hacked' WHERE id = 1--",
            "1'; DELETE FROM users WHERE id > 1--",
            "1'; CREATE TABLE hacked (id INT)--",
            
            # Boolean-based blind
            "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
            "1' AND (SELECT COUNT(*) FROM users) > 0--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "1' AND SUBSTRING(version(),1,1) = '5'--",
            "1' AND LENGTH(database()) > 0--",
            
            # Time-based blind
            "1' OR SLEEP(5)--",
            "1' WAITFOR DELAY '00:00:05'--",
            "1' AND (SELECT SLEEP(5))--",
            "1'; WAITFOR DELAY '00:00:10'--",
            "1' OR BENCHMARK(1000000,MD5(1))--",
            
            # Error-based
            "1' AND 1=CONVERT(int, (SELECT @@version))--",
            "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
            
            # System command execution
            "'; EXEC xp_cmdshell('whoami')--",
            "'; EXEC xp_cmdshell('dir')--",
            "1'; SELECT LOAD_FILE('/etc/passwd')--",
            "1'; SELECT * INTO OUTFILE '/tmp/hacked.txt'--",
            
            # Database fingerprinting
            "SELECT * FROM sqlite_master WHERE type='table'",
            "SELECT version()",
            "SELECT @@version",
            "SELECT user()",
            "SELECT database()",
            "SELECT current_user",
            
            # Advanced techniques
            "admin'/**/OR/**/'1'='1",
            "1' OR ROW(1,1) > (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND()*2)) FROM information_schema.tables GROUP BY 2)--",
            "1'+(SELECT+*+FROM+(SELECT+COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x+FROM+information_schema.tables+GROUP+BY+x)a)+'",
            "1' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1) = 'u'--",
        ]
        
        df = pd.DataFrame({'Sentence': sample_data})
        print(f"[INFO] Created sample dataset with {len(sample_data)} examples")
    
    # Create tokenizer with EXACT same parameters as your training
    tokenizer = Tokenizer(num_words=1000, oov_token='<OOV>')
    
    # Fit on the training data (exactly as in your training)
    tokenizer.fit_on_texts(df['Sentence'])
    
    # Create sequences and padded sequences (for verification)
    sequences = tokenizer.texts_to_sequences(df['Sentence'])
    padded_sequences = pad_sequences(sequences, padding='post', maxlen=30)
    
    # Save the tokenizer
    with open('tokenizer.pkl', 'wb') as f:
        pickle.dump(tokenizer, f)
    
    print("\n" + "="*50)
    print("[SUCCESS] Tokenizer saved to 'tokenizer.pkl'")
    print(f"[INFO] Vocabulary size: {len(tokenizer.word_index)}")
    print(f"[INFO] Number of words in tokenizer: {tokenizer.num_words}")
    print(f"[INFO] Max sequence length: 30")
    print(f"[INFO] OOV token: '<OOV>'")
    print(f"[INFO] Padding: 'post'")
    print("="*50)
    
    # Test the tokenizer with your exact process
    test_queries = [
        "SELECT * FROM users WHERE id = 1",
        "' OR '1'='1' --",
        "1' UNION SELECT username, password FROM users--",
        "admin'; DROP TABLE users; --"
    ]
    
    print("\n[TEST] Testing tokenizer (matching your training process):")
    print("-" * 60)
    for i, query in enumerate(test_queries, 1):
        # Exact same process as your training
        sequences = tokenizer.texts_to_sequences([query])
        padded_sequences = pad_sequences(sequences, padding='post', maxlen=30)
        
        print(f"\n{i}. Query: {query}")
        print(f"   Sequence: {sequences[0]}")
        print(f"   Padded:   {padded_sequences[0].tolist()}")
        print(f"   Length:   {len(padded_sequences[0])}")
    
    # Additional verification
    print(f"\n[STATS] Sample statistics:")
    print(f"   - Total sequences created: {len(sequences)}")
    print(f"   - Padded sequences shape: {padded_sequences.shape}")
    print(f"   - Most common words: {list(tokenizer.word_index.items())[:10]}")
    
    return tokenizer

def verify_tokenizer():
    """
    Verify the saved tokenizer works correctly
    """
    try:
        with open('tokenizer.pkl', 'rb') as f:
            loaded_tokenizer = pickle.load(f)
        
        print("\n[SUCCESS] Tokenizer verification successful!")
        print(f"   - Vocabulary size: {len(loaded_tokenizer.word_index)}")
        print(f"   - Num words: {loaded_tokenizer.num_words}")
        print(f"   - OOV token: {loaded_tokenizer.oov_token}")
        
        # Test with a sample query
        test_query = "SELECT * FROM users WHERE id = 1"
        sequences = loaded_tokenizer.texts_to_sequences([test_query])
        padded = pad_sequences(sequences, padding='post', maxlen=30)
        
        print(f"   - Test query processed successfully: {padded[0][:10]}...")
        return True
        
    except Exception as e:
        print(f"[ERROR] Tokenizer verification failed: {str(e)}")
        return False

if __name__ == "__main__":
    print("Creating tokenizer with your exact training configuration...")
    print("Parameters: num_words=1000, oov_token='<OOV>', maxlen=30, padding='post'")
    print("-" * 70)
    
    tokenizer = create_and_save_tokenizer()
    
    print("\nVerifying saved tokenizer...")
    verify_tokenizer()
    
    print("\nTokenizer creation complete!")
    print("You can now run your Flask API with the correct tokenizer.")
