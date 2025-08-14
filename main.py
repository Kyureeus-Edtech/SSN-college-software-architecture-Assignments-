from connectors.abuseipdb_connector import check_ip

if __name__ == "__main__":
    # Example: Google DNS. Replace with any IP you want to test.
    ip_to_check = "8.8.8.8"
    try:
        result = check_ip(ip_to_check)
        print("=== AbuseIPDB Result ===")
        print(result)  # prints JSON dict
    except Exception as e:
        print(f"Error: {e}")
