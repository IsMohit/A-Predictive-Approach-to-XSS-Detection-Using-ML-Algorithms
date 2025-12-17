# test_xss_api.py
"""
Comprehensive test script for XSS Detection API
Tests all endpoints and validates functionality
"""

import requests
import json
import time
from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)

API_BASE_URL = 'http://localhost:5000'

class XSSAPITester:
    def __init__(self, base_url=API_BASE_URL):
        self.base_url = base_url
        self.passed = 0
        self.failed = 0
        
    def print_header(self, text):
        """Print a formatted header"""
        print("\n" + "="*80)
        print(f"{Fore.CYAN}{Style.BRIGHT}{text}")
        print("="*80)
    
    def print_test(self, name):
        """Print test name"""
        print(f"\n{Fore.YELLOW}Testing: {name}")
        print("-" * 80)
    
    def print_success(self, message):
        """Print success message"""
        print(f"{Fore.GREEN}✅ PASS: {message}")
        self.passed += 1
    
    def print_failure(self, message):
        """Print failure message"""
        print(f"{Fore.RED}❌ FAIL: {message}")
        self.failed += 1
    
    def print_info(self, message):
        """Print info message"""
        print(f"{Fore.BLUE}ℹ️  {message}")
    
    def test_health_check(self):
        """Test /health endpoint"""
        self.print_test("Health Check Endpoint")
        
        try:
            response = requests.get(f"{self.base_url}/health")
            
            if response.status_code == 200:
                data = response.json()
                self.print_success(f"Health endpoint returned 200")
                self.print_info(f"Status: {data.get('status')}")
                self.print_info(f"Model loaded: {data.get('model_loaded')}")
                
                if data.get('model_loaded'):
                    self.print_success("Model is loaded and ready")
                else:
                    self.print_failure("Model not loaded")
            else:
                self.print_failure(f"Unexpected status code: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            self.print_failure("Could not connect to API. Is the server running?")
        except Exception as e:
            self.print_failure(f"Error: {str(e)}")
    
    def test_root_endpoint(self):
        """Test / endpoint"""
        self.print_test("Root Endpoint Documentation")
        
        try:
            response = requests.get(f"{self.base_url}/")
            
            if response.status_code == 200:
                data = response.json()
                self.print_success("Root endpoint accessible")
                self.print_info(f"Service: {data.get('service')}")
                self.print_info(f"Version: {data.get('version')}")
                self.print_info(f"Available endpoints: {len(data.get('endpoints', {}))}")
            else:
                self.print_failure(f"Unexpected status code: {response.status_code}")
                
        except Exception as e:
            self.print_failure(f"Error: {str(e)}")
    
    def test_safe_inputs(self):
        """Test with safe inputs"""
        self.print_test("Safe Input Detection")
        
        safe_inputs = [
            "Hello, how are you?",
            "This is a normal comment",
            "Welcome to my website!",
            "Contact me at email@example.com",
            "Check out https://example.com"
        ]
        
        for input_text in safe_inputs:
            try:
                response = requests.post(
                    f"{self.base_url}/check",
                    json={'input': input_text}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    prediction = data.get('prediction')
                    confidence = data.get('confidence')
                    
                    if prediction == 'safe':
                        self.print_success(f"Correctly identified as safe: '{input_text[:40]}...' ({confidence}%)")
                    else:
                        self.print_failure(f"False positive: '{input_text[:40]}...' detected as {prediction}")
                else:
                    self.print_failure(f"API error: {response.status_code}")
                    
            except Exception as e:
                self.print_failure(f"Error: {str(e)}")
    
    def test_malicious_inputs(self):
        """Test with malicious XSS inputs"""
        self.print_test("Malicious Input Detection")
        
        malicious_inputs = [
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(document.cookie)",
            "<iframe src='javascript:alert(1)'>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert(1) autofocus>"
        ]
        
        for input_text in malicious_inputs:
            try:
                response = requests.post(
                    f"{self.base_url}/check",
                    json={'input': input_text}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    prediction = data.get('prediction')
                    confidence = data.get('confidence')
                    sanitized = data.get('sanitized')
                    
                    if prediction == 'malicious':
                        self.print_success(f"Correctly detected XSS: '{input_text[:40]}...' ({confidence}%)")
                        self.print_info(f"Sanitized to: '{sanitized}'")
                    else:
                        self.print_failure(f"False negative: '{input_text[:40]}...' detected as {prediction}")
                else:
                    self.print_failure(f"API error: {response.status_code}")
                    
            except Exception as e:
                self.print_failure(f"Error: {str(e)}")
    
    def test_batch_check(self):
        """Test /batch-check endpoint"""
        self.print_test("Batch Check Endpoint")
        
        test_inputs = [
            "Hello world",
            "<script>alert(1)</script>",
            "Normal text here",
            "<img src=x onerror=alert(1)>"
        ]
        
        try:
            response = requests.post(
                f"{self.base_url}/batch-check",
                json={'inputs': test_inputs}
            )
            
            if response.status_code == 200:
                data = response.json()
                total = data.get('total')
                results = data.get('results', [])
                
                self.print_success(f"Batch check processed {total} inputs")
                
                for result in results:
                    idx = result.get('index')
                    pred = result.get('prediction')
                    conf = result.get('confidence')
                    self.print_info(f"Input {idx}: {pred} ({conf}%)")
                
                if len(results) == len(test_inputs):
                    self.print_success("All inputs processed in batch")
                else:
                    self.print_failure("Some inputs missing from batch results")
            else:
                self.print_failure(f"Batch check failed: {response.status_code}")
                
        except Exception as e:
            self.print_failure(f"Error: {str(e)}")
    
    def test_empty_input(self):
        """Test with empty input"""
        self.print_test("Empty Input Handling")
        
        try:
            response = requests.post(
                f"{self.base_url}/check",
                json={'input': ''}
            )
            
            if response.status_code == 200:
                data = response.json()
                self.print_success("Empty input handled gracefully")
                self.print_info(f"Prediction: {data.get('prediction')}")
            else:
                self.print_failure(f"Empty input not handled: {response.status_code}")
                
        except Exception as e:
            self.print_failure(f"Error: {str(e)}")
    
    def test_invalid_request(self):
        """Test with invalid request format"""
        self.print_test("Invalid Request Handling")
        
        try:
            # Missing 'input' field
            response = requests.post(
                f"{self.base_url}/check",
                json={'wrong_field': 'test'}
            )
            
            if response.status_code == 400:
                self.print_success("Invalid request properly rejected with 400")
                data = response.json()
                self.print_info(f"Error message: {data.get('error')}")
            else:
                self.print_failure(f"Expected 400, got {response.status_code}")
                
        except Exception as e:
            self.print_failure(f"Error: {str(e)}")
    
    def test_response_time(self):
        """Test API response time"""
        self.print_test("Response Time Performance")
        
        test_input = "<script>alert('performance test')</script>"
        times = []
        
        for i in range(10):
            start_time = time.time()
            try:
                response = requests.post(
                    f"{self.base_url}/check",
                    json={'input': test_input}
                )
                end_time = time.time()
                
                if response.status_code == 200:
                    elapsed = (end_time - start_time) * 1000  # Convert to ms
                    times.append(elapsed)
            except Exception as e:
                self.print_failure(f"Error during performance test: {str(e)}")
                return
        
        if times:
            avg_time = sum(times) / len(times)
            min_time = min(times)
            max_time = max(times)
            
            self.print_info(f"Average response time: {avg_time:.2f}ms")
            self.print_info(f"Min: {min_time:.2f}ms | Max: {max_time:.2f}ms")
            
            if avg_time < 100:
                self.print_success("Response time is excellent (<100ms)")
            elif avg_time < 500:
                self.print_success("Response time is good (<500ms)")
            else:
                self.print_failure(f"Response time is slow (>{avg_time:.2f}ms)")
    
    def test_stats_endpoint(self):
        """Test /stats endpoint"""
        self.print_test("Statistics Endpoint")
        
        try:
            response = requests.get(f"{self.base_url}/stats")
            
            if response.status_code == 200:
                data = response.json()
                self.print_success("Stats endpoint accessible")
                self.print_info(f"Total logged attempts: {data.get('total_attempts', 0)}")
                self.print_info(f"High confidence: {data.get('high_confidence_attempts', 0)}")
            else:
                self.print_failure(f"Stats endpoint error: {response.status_code}")
                
        except Exception as e:
            self.print_failure(f"Error: {str(e)}")
    
    def run_all_tests(self):
        """Run all tests"""
        self.print_header("🧪 XSS Detection API Test Suite")
        
        print(f"\n{Fore.CYAN}Target API: {self.base_url}")
        print(f"{Fore.CYAN}Starting comprehensive tests...\n")
        
        # Run all test methods
        self.test_health_check()
        self.test_root_endpoint()
        self.test_safe_inputs()
        self.test_malicious_inputs()
        self.test_batch_check()
        self.test_empty_input()
        self.test_invalid_request()
        self.test_response_time()
        self.test_stats_endpoint()
        
        # Print summary
        self.print_header("📊 Test Summary")
        total_tests = self.passed + self.failed
        pass_rate = (self.passed / total_tests * 100) if total_tests > 0 else 0
        
        print(f"\n{Fore.GREEN}Passed: {self.passed}")
        print(f"{Fore.RED}Failed: {self.failed}")
        print(f"{Fore.CYAN}Total: {total_tests}")
        print(f"{Fore.YELLOW}Pass Rate: {pass_rate:.1f}%\n")
        
        if self.failed == 0:
            print(f"{Fore.GREEN}{Style.BRIGHT}🎉 All tests passed! System is working correctly.")
        else:
            print(f"{Fore.YELLOW}{Style.BRIGHT}⚠️  Some tests failed. Please review the errors above.")
        
        print("\n" + "="*80 + "\n")


if __name__ == "__main__":
    print(f"{Fore.CYAN}{Style.BRIGHT}")
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║         XSS Detection API - Test Suite v1.0              ║
    ║         Comprehensive Testing Framework                   ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    print(Style.RESET_ALL)
    
    # Check if colorama is installed, if not provide instructions
    try:
        from colorama import init
    except ImportError:
        print("⚠️  For colored output, install colorama: pip install colorama")
        print("    Tests will continue without colored output.\n")
    
    tester = XSSAPITester()
    tester.run_all_tests()