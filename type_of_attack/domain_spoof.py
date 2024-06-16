from detection.detect_domainspoof import test_domain_spoofing

    # Define a list of URLs to test
    urls_to_test = [
        'https://www.example.com',
        'https://www.suspicious-domain.com',
        'https://www.legitimate-domain.com',
        # Add more URLs as needed
    ]

    # Call the test_domain_spoofing function with the list of URLs
    results = test_domain_spoofing(urls_to_test)

    # Print the results
    for url, result in results.items():
        print(f"URL: {url} - Result: {result}")
except ImportError as e:
    print(f"Error importing module: {e}")
except Exception as e:
    print(f"An error occurred: {e}")
