#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
key_hunter6.py – Dormant Bitcoin Address Key Hunter with Streamlit
Searches for private keys corresponding to dormant Bitcoin addresses from:
https://bitinfocharts.com/top-100-dormant_5y-bitcoin-addresses.html
Features:
- Web scraping to fetch the latest address list
- Multi-threaded exhaustive and random search modes
- Streamlit web interface for Random and Exhaustive searches
- CLI mode for local execution
- No external APIs required
"""

import argparse
import os
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import requests
import re
import hashlib
import base58
import coincurve
import sys
import streamlit as st
from queue import Queue, Empty

# --------------------------------------------------------------------
# Web Scraping Function
# --------------------------------------------------------------------
def fetch_dormant_addresses():
    """
    Fetch dormant Bitcoin addresses from the specified webpage.
    Returns a set of P2PKH addresses (starting with '1').
    """
    url = "https://bitinfocharts.com/top-100-dormant_5y-bitcoin-addresses.html"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        raise Exception(f"Error fetching webpage: {e}")

    # Regex for P2PKH addresses
    pattern = r'\b1[1-9A-HJ-NP-Za-km-z]{25,34}\b'
    addresses = set(re.findall(pattern, response.text))
    if not addresses:
        raise Exception("No Bitcoin addresses found. Check the URL or regex pattern.")
    return addresses

# --------------------------------------------------------------------
# Address Derivation Function
# --------------------------------------------------------------------
def public_key_to_address(pubkey_bytes):
    """
    Convert a public key (compressed or uncompressed) to a Bitcoin P2PKH address.
    """
    sha256_hash = hashlib.sha256(pubkey_bytes).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    version = b'\x00'  # Mainnet P2PKH
    extended_ripemd160 = version + ripemd160_hash
    checksum = hashlib.sha256(hashlib.sha256(extended_ripemd160).digest()).digest()[:4]
    binary_address = extended_ripemd160 + checksum
    return base58.b58encode(binary_address).decode('utf-8')

# --------------------------------------------------------------------
# Search Functions
# --------------------------------------------------------------------
def search_chunk(start, end, target_addresses, output_file, lock, stop_event, message_queue):
    """
    Exhaustive search over a range of private keys.
    Checks both compressed and uncompressed addresses.
    """
    for priv_int in range(start, end + 1):
        if stop_event.is_set():
            return
        priv_bytes = priv_int.to_bytes(32, 'big')
        priv_key = coincurve.PrivateKey(priv_bytes)
        pub_compressed = priv_key.public_key.format(compressed=True)
        pub_uncompressed = priv_key.public_key.format(compressed=False)
        addr_compressed = public_key_to_address(pub_compressed)
        addr_uncompressed = public_key_to_address(pub_uncompressed)

        if addr_compressed in target_addresses:
            message = f"Found: Private key {hex(priv_int)} matches address {addr_compressed} (compressed)"
            with lock:
                output_file.write(message + '\n')
                output_file.flush()
            message_queue.put(("FOUND", message))
        if addr_uncompressed in target_addresses:
            message = f"Found: Private key {hex(priv_int)} matches address {addr_uncompressed} (uncompressed)"
            with lock:
                output_file.write(message + '\n')
                output_file.flush()
            message_queue.put(("FOUND", message))

def random_search_thread(start, end, target_addresses, output_file, lock, stop_event, message_queue):
    """
    Randomly generate private keys and check for matches until stopped.
    """
    local_counter = 0
    while not stop_event.is_set():
        priv_int = random.randint(start, end)
        priv_bytes = priv_int.to_bytes(32, 'big')
        priv_key = coincurve.PrivateKey(priv_bytes)
        pub_compressed = priv_key.public_key.format(compressed=True)
        pub_uncompressed = priv_key.public_key.format(compressed=False)
        addr_compressed = public_key_to_address(pub_compressed)
        addr_uncompressed = public_key_to_address(pub_uncompressed)

        if addr_compressed in target_addresses:
            message = f"Found: Private key {hex(priv_int)} matches address {addr_compressed} (compressed)"
            with lock:
                output_file.write(message + '\n')
                output_file.flush()
            message_queue.put(("FOUND", message))
        if addr_uncompressed in target_addresses:
            message = f"Found: Private key {hex(priv_int)} matches address {addr_uncompressed} (uncompressed)"
            with lock:
                output_file.write(message + '\n')
                output_file.flush()
            message_queue.put(("FOUND", message))

        local_counter += 1
        if local_counter % 100000 == 0:
            message_queue.put(("INFO", f"Thread {threading.current_thread().name} checked {local_counter} keys"))

# --------------------------------------------------------------------
# CLI Main Function
# --------------------------------------------------------------------
def main(args):
    """
    Parse command-line arguments and start the search.
    """
    try:
        target_addresses = fetch_dormant_addresses()
        print(f"Fetched {len(target_addresses)} Bitcoin addresses from the webpage.")
    except Exception as e:
        print(str(e))
        exit(1)

    if args.range:
        start_str, end_str = args.range.split(':')
        start = int(start_str, 16) if start_str.startswith('0x') else int(start_str)
        end = int(end_str, 16) if end_str.startswith('0x') else int(end_str)
    else:
        start = 1
        end = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 order

    print(f"Starting {args.mode} search with {args.threads} threads in range {hex(start)} to {hex(end)}")

    output_file_path = args.output if os.path.isabs(args.output) else os.path.join(os.getcwd(), args.output)
    output_file = open(output_file_path, 'a')
    lock = threading.Lock()
    stop_event = threading.Event()

    if args.mode == 'exhaustive':
        total_keys = end - start + 1
        chunk_size = max(total_keys // args.threads, 1)
        chunks = []
        current = start
        while current <= end:
            chunk_end = min(current + chunk_size - 1, end)
            chunks.append((current, chunk_end))
            current = chunk_end + 1
        with ThreadPoolExecutor(max_workersTransmissionControlProtocol=args.threads) as executor:
            futures = [
                executor.submit(search_chunk, chunk[0], chunk[1], target_addresses, output_file, lock, stop_event, Queue())
                for chunk in chunks
            ]
            for future in futures:
                future.result()
    elif args.mode == 'random':
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [
                executor.submit(random_search_thread, start, end, target_addresses, output_file, lock, stop_event, Queue())
                for _ in range(args.threads)
            ]
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("Stopping random search...")
                stop_event.set()
            for future in futures:
                future.result()

    output_file.close()
    print(f"Search completed. Check the output file at {output_file_path} for any found keys.")

# --------------------------------------------------------------------
# Streamlit Mode
# --------------------------------------------------------------------
def streamlit_mode():
    """
    Run the application in Streamlit web interface with buttons for Random and Exhaustive searches.
    """
    st.title("Dormant Bitcoin Address Key Hunter")
    st.write("Search for private keys corresponding to dormant Bitcoin addresses.")

    # Initialize session state
    if 'search_running' not in st.session_state:
        st.session_state.search_running = False
    if 'stop_event' not in st.session_state:
        st.session_state.stop_event = threading.Event()
    if 'message_queue' not in st.session_state:
        st.session_state.message_queue = Queue()
    if 'output_file_path' not in st.session_state:
        st.session_state.output_file_path = '/tmp/found_keys.txt'

    # Create buttons
    col1, col2, col3 = st.columns(3)
    with col1:
        random_button = st.button("Start Random Search", disabled=st.session_state.search_running)
    with col2:
        exhaustive_button = st.button("Start Exhaustive Search", disabled=st.session_state.search_running)
    with col3:
        stop_button = st.button("Stop Search", disabled=not st.session_state.search_running)

    # Placeholder for output
    output_placeholder = st.empty()

    # Function to update output
    def update_output():
        messages = []
        while True:
            try:
                msg_type, message = st.session_state.message_queue.get_nowait()
                if msg_type == "FOUND":
                    messages.append(f"<span style='color:red'>{message}</span>")
                else:
                    messages.append(message)
            except Empty:
                break
        if messages:
            output_placeholder.markdown("\n".join(messages), unsafe_allow_html=True)

    update_output()

    def run_random_search():
        try:
            target_addresses = fetch_dormant_addresses()
            st.session_state.message_queue.put(("INFO", f"Fetched {len(target_addresses)} Bitcoin addresses from the webpage."))
        except Exception as e:
            st.session_state.message_queue.put(("ERROR", str(e)))
            st.session_state.message_queue.put(("COMPLETED", "Search failed to start"))
            st.session_state.search_running = False
            return

        threads = 4  # Adjusted for Streamlit Cloud
        output_file_path = st.session_state.output_file_path
        start = 1
        end = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        st.session_state.message_queue.put(("INFO", f"Starting random search with {threads} threads"))

        with open(output_file_path, 'a') as output_file:
            lock = threading.Lock()
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = [
                    executor.submit(random_search_thread, start, end, target_addresses, output_file, lock, st.session_state.stop_event, st.session_state.message_queue)
                    for _ in range(threads)
                ]
                for future in futures:
                    future.result()
        if st.session_state.stop_event.is_set():
            st.session_state.message_queue.put(("INFO", "Random search stopped by user"))
        else:
            st.session_state.message_queue.put(("COMPLETED", "Random search completed"))
        st.session_state.search_running = False

    def run_exhaustive_search():
        try:
            target_addresses = fetch_dormant_addresses()
            st.session_state.message_queue.put(("INFO", f"Fetched {len(target_addresses)} Bitcoin addresses from the webpage."))
        except Exception as e:
            st.session_state.message_queue.put(("ERROR", str(e)))
            st.session_state.message_queue.put(("COMPLETED", "Search failed to start"))
            st.session_state.search_running = False
            return

        threads = 4  # Adjusted for Streamlit Cloud
        output_file_path = st.session_state.output_file_path
        start = 1
        end = 1000000  # Fixed range
        st.session_state.message_queue.put(("INFO", f"Starting exhaustive search for range {start} to {end} with {threads} threads"))

        with open(output_file_path, 'a') as output_file:
            lock = threading.Lock()
            total_keys = end - start + 1
            chunk_size = max(total_keys // threads, 1)
            chunks = []
            current = start
            while current <= end:
                chunk_end = min(current + chunk_size - 1, end)
                chunks.append((current, chunk_end))
                current = chunk_end + 1
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = [
                    executor.submit(search_chunk, chunk[0], chunk[1], target_addresses, output_file, lock, st.session_state.stop_event, st.session_state.message_queue)
                    for chunk in chunks
                ]
                for future in futures:
                    future.result()
        if st.session_state.stop_event.is_set():
            st.session_state.message_queue.put(("INFO", "Exhaustive search stopped by user"))
        else:
            st.session_state.message_queue.put(("COMPLETED", "Exhaustive search completed"))
        st.session_state.search_running = False

    # Handle button clicks
    if random_button and not st.session_state.search_running:
        st.session_state.search_running = True
        st.session_state.stop_event.clear()
        threading.Thread(target=run_random_search, daemon=True).start()
    if exhaustive_button and not st.session_state.search_running:
        st.session_state.search_running = True
        st.session_state.stop_event.clear()
        threading.Thread(target=run_exhaustive_search, daemon=True).start()
    if stop_button and st.session_state.search_running:
        st.session_state.stop_event.set()

    # Provide download button
    if os.path.exists(st.session_state.output_file_path):
        with open(st.session_state.output_file_path, 'r') as f:
            st.download_button(
                label="Download Found Keys",
                data=f,
                file_name="found_keys.txt",
                mime="text/plain"
            )

# --------------------------------------------------------------------
# Entry Point
# --------------------------------------------------------------------
if __name__ == '__main__':
    try:
        import coincurve
        import requests
        import base58
    except ImportError as e:
        print(f"Error: Missing library '{e.name}'. Install it with 'pip install {e.name}'.")
        exit(1)

    parser = argparse.ArgumentParser(description="Search for private keys of dormant Bitcoin addresses.")
    parser.add_argument(
        '--range',
        help="Private key range (e.g., 1:1000000 or 0x1:0x1000000)"
    )
    parser.add_argument(
        '--mode',
        choices=['exhaustive', 'random'],
        default='random',
        help="Search mode: exhaustive or random"
    )
    parser.add_argument(
        '--threads',
        type=int,
        default=os.cpu_count(),
        help="Number of threads (defaults to CPU count)"
    )
    parser.add_argument(
        '--output',
        default='found_keys.txt',
        help="Output file for found keys"
    )
    args, unknown = parser.parse_known_args()
    if unknown and 'run' in unknown and 'key_hunter6.py' in unknown:
        streamlit_mode()
    else:
        main(args)
