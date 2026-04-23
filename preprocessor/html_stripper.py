import html
import unittest
from html.parser import HTMLParser

class HTMLStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self.reset()
        self.text_data = []
        self.ignore_tags = {'script', 'style', 'noscript', 'iframe', 'svg'}
        self.skip_current = False
        self.inside_pre = False

    def handle_starttag(self, tag, attrs):
        if tag in self.ignore_tags:
            self.skip_current = True
            
        if tag in ('pre', 'code'):
            self.inside_pre = True
            
        if tag == 'a' and not self.skip_current:
            for attr, value in attrs:
                if attr == 'href' and value.startswith('http'):
                    self.text_data.append((f" [{value}] ", False))

    def handle_endtag(self, tag):
        if tag in self.ignore_tags:
            self.skip_current = False
            
        if tag in ('pre', 'code'):
            self.inside_pre = False

    def handle_data(self, data):
        if not self.skip_current:
            self.text_data.append((data, self.inside_pre))

    def get_clean_text(self):
        result = []
        for text, is_pre in self.text_data:
            if is_pre:
                result.append(text)
            else:
                cleaned = ' '.join(text.split())
                if cleaned:
                    result.append(cleaned)
        return ' '.join(result).strip()

def strip_html(raw_html: str) -> str:
    if not raw_html or not isinstance(raw_html, str):
        return ""
    
    try:
        decoded_html = html.unescape(raw_html)
        stripper = HTMLStripper()
        stripper.feed(decoded_html)
        return stripper.get_clean_text()
        
    except Exception as e:
        print(f"[!] Error: {e}")
        return raw_html

class TestHTMLStripper(unittest.TestCase):
    def test_basic_tag_stripping(self):
        self.assertEqual(strip_html("<div><h1>Title</h1><p>Test.</p></div>"), "Title Test.")

    def test_whitespace_normalization(self):
        self.assertEqual(strip_html("<p>   Some \n\n data \t.   </p>"), "Some data .")

    def test_ignore_malicious_tags(self):
        raw = "<script>alert(1);</script><style>body{}</style><p>Text</p>"
        self.assertEqual(strip_html(raw), "Text")

    def test_html_entity_unescaping(self):
        self.assertEqual(strip_html("&lt;script&gt; &amp; &quot;admin&quot;"), "<script> & \"admin\"")

    def test_link_extraction(self):
        raw = '<a href="https://example.com/patch">Link</a>'
        self.assertEqual(strip_html(raw), "[https://example.com/patch] Link")

    def test_pre_code_preservation(self):
        raw = "<pre>line1\n  line2</pre>"
        self.assertEqual(strip_html(raw), "line1\n  line2")

    def test_empty_inputs(self):
        self.assertEqual(strip_html(""), "")
        self.assertEqual(strip_html(None), "")

if __name__ == "__main__":
    unittest.main(verbosity=2)