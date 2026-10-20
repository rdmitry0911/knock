"""Package translation completeness and interpolation safety."""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
LANGUAGES = {'en', 'ru', 'de', 'fr', 'es', 'pt_BR', 'zh_CN', 'ja', 'ar', 'hi'}

class LocalizationTests(unittest.TestCase):
    def test_all_languages_have_complete_messages_and_matching_placeholders(self):
        directory = ROOT / 'extension/_locales'
        self.assertEqual({p.name for p in directory.iterdir() if p.is_dir()}, LANGUAGES)
        english = json.loads((directory / 'en/messages.json').read_text())
        for language in LANGUAGES:
            messages = json.loads((directory / language / 'messages.json').read_text())
            self.assertEqual(set(messages), set(english), language)
            for key, value in messages.items():
                self.assertTrue(value['message'].strip(), (language, key))
                self.assertEqual(set(re.findall(r'\{\w+\}', value['message'])),
                    set(re.findall(r'\{\w+\}', english[key]['message'])), (language, key))

    def test_russian_text_is_confined_to_translation_catalogs(self):
        for name in ('extension', 'controller', 'src', 'scripts', 'packaging'):
            for path in (ROOT / name).rglob('*'):
                if not path.is_file() or path.suffix not in {'.js', '.html', '.py', '.sh', '.c', '.h', '.webmanifest'}:
                    continue
                if 'vendor' in path.parts:
                    continue
                self.assertNotRegex(path.read_text(), r'[\u0400-\u04ff]', str(path))
