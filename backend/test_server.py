import requests
import json

def test_password_analysis():
    url = 'http://localhost:5000/api/analyze-password'
    test_password = "TestPassword123!"
    
    try:
        response = requests.post(
            url,
            json={'password': test_password},
            headers={'Content-Type': 'application/json'}
        )
        
        print(f"Status Code: {response.status_code}")
        print("Response Headers:", json.dumps(dict(response.headers), indent=2))
        print("Response Body:", json.dumps(response.json(), indent=2))
        
        if response.ok:
            print("\n✅ Server is running and responding correctly!")
        else:
            print("\n❌ Server returned an error response")
            
    except requests.exceptions.ConnectionError:
        print("\n❌ Could not connect to server. Make sure it's running on port 5000")
    except Exception as e:
        print(f"\n❌ Test failed: {str(e)}")

if __name__ == "__main__":
    print("Testing password analysis endpoint...")
    test_password_analysis() 