#!/usr/bin/env python3
"""
Test script for dynamic security gateway mode switching
"""

import requests
import json
import time
import sys

def test_security_api(base_url="http://localhost:8080"):
    """Test the security gateway API endpoints"""
    
    print("🔒 Testing Dynamic Security Gateway System")
    print("=" * 50)
    
    # Test 1: Get current status
    print("\n1. Getting security gateway status...")
    try:
        response = requests.get(f"{base_url}/api/security/status")
        if response.status_code == 200:
            status = response.json()
            print(f"✅ Status: {json.dumps(status, indent=2)}")
        else:
            print(f"❌ Failed to get status: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error getting status: {e}")
        return False
    
    # Test 2: Get available modes
    print("\n2. Getting available security modes...")
    try:
        response = requests.get(f"{base_url}/api/security/modes")
        if response.status_code == 200:
            modes = response.json()
            print(f"✅ Available modes: {json.dumps(modes, indent=2)}")
        else:
            print(f"❌ Failed to get modes: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error getting modes: {e}")
        return False
    
    # Test 3: Get current mode
    print("\n3. Getting current security mode...")
    try:
        response = requests.get(f"{base_url}/api/security/mode")
        if response.status_code == 200:
            mode = response.json()
            print(f"✅ Current mode: {json.dumps(mode, indent=2)}")
            current_mode = mode['mode']
        else:
            print(f"❌ Failed to get current mode: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error getting current mode: {e}")
        return False
    
    # Test 4: Switch to different modes
    test_modes = ['disabled', 'monitor', 'audit', 'enforce']
    
    for test_mode in test_modes:
        print(f"\n4.{test_modes.index(test_mode) + 1}. Switching to '{test_mode}' mode...")
        try:
            response = requests.post(
                f"{base_url}/api/security/mode",
                json={"mode": test_mode},
                headers={"Content-Type": "application/json"}
            )
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Successfully switched to '{test_mode}': {result['message']}")
                
                # Verify the change
                verify_response = requests.get(f"{base_url}/api/security/mode")
                if verify_response.status_code == 200:
                    verify_mode = verify_response.json()
                    if verify_mode['mode'] == test_mode:
                        print(f"✅ Mode change verified: {verify_mode['mode']}")
                    else:
                        print(f"❌ Mode change not verified: expected {test_mode}, got {verify_mode['mode']}")
                        return False
                else:
                    print(f"❌ Failed to verify mode change: {verify_response.status_code}")
                    return False
            else:
                print(f"❌ Failed to switch to '{test_mode}': {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"❌ Error switching to '{test_mode}': {e}")
            return False
        
        # Small delay between mode changes
        time.sleep(0.5)
    
    # Test 5: Try invalid mode
    print(f"\n5. Testing invalid mode...")
    try:
        response = requests.post(
            f"{base_url}/api/security/mode",
            json={"mode": "invalid_mode"},
            headers={"Content-Type": "application/json"}
        )
        if response.status_code == 400:
            error = response.json()
            print(f"✅ Invalid mode correctly rejected: {error['error']}")
        else:
            print(f"❌ Invalid mode should have been rejected: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error testing invalid mode: {e}")
        return False
    
    # Test 6: Restore original mode
    print(f"\n6. Restoring original mode '{current_mode}'...")
    try:
        response = requests.post(
            f"{base_url}/api/security/mode",
            json={"mode": current_mode},
            headers={"Content-Type": "application/json"}
        )
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Restored original mode: {result['message']}")
        else:
            print(f"❌ Failed to restore original mode: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error restoring original mode: {e}")
        return False
    
    print("\n" + "=" * 50)
    print("🎉 All security gateway tests passed!")
    print("✅ Dynamic mode switching is working correctly")
    return True

def test_health_check(base_url="http://localhost:8080"):
    """Test if the backend is running"""
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        return response.status_code == 200
    except:
        return False

if __name__ == "__main__":
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    
    print(f"Testing backend at: {base_url}")
    
    # Check if backend is running
    if not test_health_check(base_url):
        print("❌ Backend is not running or not accessible")
        print("Please start the backend with: python main.py")
        sys.exit(1)
    
    print("✅ Backend is running")
    
    # Run security tests
    if test_security_api(base_url):
        print("\n🎯 Dynamic Security Gateway System is fully functional!")
        sys.exit(0)
    else:
        print("\n💥 Some tests failed!")
        sys.exit(1)
