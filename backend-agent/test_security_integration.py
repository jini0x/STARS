#!/usr/bin/env python3
"""
Test script for Security Gateway integration with STARS backend.
This script tests the security gateway integration without requiring a running gateway.
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_security_gateway_disabled():
    """Test security gateway when disabled"""
    print("Testing Security Gateway (Disabled)...")
    
    # Set environment to disable security gateway
    os.environ['SECURITY_GATEWAY_ENABLED'] = 'false'
    
    from security_gateway import get_security_gateway
    
    gateway = get_security_gateway()
    
    # Test that gateway is disabled
    assert not gateway.is_enabled(), "Gateway should be disabled"
    
    # Test input analysis returns ALLOW when disabled
    result = gateway.analyze_input("Test prompt", {"model": "test"})
    assert result.recommendation == "ALLOW", "Should allow when disabled"
    assert result.analysis_id is None, "Should have no analysis ID when disabled"
    
    # Test output analysis returns ALLOW when disabled
    result = gateway.analyze_output("Test response", None, {"model": "test"})
    assert result.recommendation == "ALLOW", "Should allow when disabled"
    
    print("✅ Security Gateway (Disabled) tests passed!")

def test_security_gateway_enabled_no_server():
    """Test security gateway when enabled but no server running"""
    print("Testing Security Gateway (Enabled, No Server)...")
    
    # Set environment to enable security gateway
    os.environ['SECURITY_GATEWAY_ENABLED'] = 'true'
    os.environ['SECURITY_GATEWAY_URL'] = 'http://localhost:9999/api/v1'  # Non-existent server
    os.environ['SECURITY_GATEWAY_TIMEOUT'] = '1'  # Short timeout
    
    # Clear the global instance to force recreation
    import security_gateway
    security_gateway._security_gateway = None
    
    gateway = security_gateway.get_security_gateway()
    
    # Test that gateway is enabled
    assert gateway.is_enabled(), "Gateway should be enabled"
    
    # Test input analysis gracefully handles connection error
    result = gateway.analyze_input("Test prompt", {"model": "test"})
    assert result.recommendation == "ALLOW", "Should allow on connection error"
    assert result.error is not None, "Should have error message"
    
    # Test output analysis gracefully handles connection error
    result = gateway.analyze_output("Test response", None, {"model": "test"})
    assert result.recommendation == "ALLOW", "Should allow on connection error"
    assert result.error is not None, "Should have error message"
    
    print("✅ Security Gateway (Enabled, No Server) tests passed!")

def test_llm_integration():
    """Test LLM integration with security gateway"""
    print("Testing LLM Integration...")
    
    # Set environment to disable security gateway for this test
    os.environ['SECURITY_GATEWAY_ENABLED'] = 'false'
    
    # Clear the global instance
    import security_gateway
    security_gateway._security_gateway = None
    
    from llm_response import Success
    from llm import LLM
    
    # Create a mock LLM class for testing
    class MockLLM(LLM):
        def __init__(self):
            self.model_name = "test-model"
        
        def __str__(self):
            return "Mock LLM for testing"
        
        def generate(self, system_prompt: str, prompt: str, **kwargs):
            # This won't be called in our test
            pass
        
        def generate_completions_for_messages(self, messages: list, **kwargs):
            # This won't be called in our test
            pass
    
    # Test the _trace_llm_call method
    mock_llm = MockLLM()
    
    # Test with string prompt
    test_prompt = "Test prompt"
    test_response = Success(["Test response"])
    
    result = mock_llm._trace_llm_call(test_prompt, test_response)
    assert result == test_response, "Should return the same response"
    
    # Test with message-style prompt
    test_messages = [
        {"role": "system", "content": "You are a helpful assistant"},
        {"role": "user", "content": "Hello"}
    ]
    
    result = mock_llm._trace_llm_call(test_messages, test_response)
    assert result == test_response, "Should return the same response"
    
    print("✅ LLM Integration tests passed!")

def main():
    """Run all tests"""
    print("🔒 STARS Security Gateway Integration Tests")
    print("=" * 50)
    
    try:
        test_security_gateway_disabled()
        test_security_gateway_enabled_no_server()
        test_llm_integration()
        
        print("\n🎉 All tests passed!")
        print("\nIntegration Summary:")
        print("- Security Gateway client created successfully")
        print("- LLM wrapper integration completed")
        print("- Environment configuration added")
        print("- Graceful error handling implemented")
        print("\nTo use the security gateway:")
        print("1. Deploy your security gateway service")
        print("2. Update SECURITY_GATEWAY_URL in your .env file")
        print("3. Set SECURITY_GATEWAY_ENABLED=true")
        print("4. Run your STARS backend normally")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
