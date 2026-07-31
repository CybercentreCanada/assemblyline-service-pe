"""Sublanguage naming for Windows resource language identifiers.

LIEF removed the RESOURCE_SUBLANGS enum and its (language, sublanguage) resolution table in
0.14.0, but the numeric sublanguage (the top 6 bits of a resource language identifier) is
still available. This restores the naming, generated from the SUBLANG_* constants in winnt.h
(mingw-w64 headers), which follow
https://learn.microsoft.com/en-us/windows/win32/intl/language-identifier-constants-and-strings
"""

# Sublanguage meaning depends on the primary language: (primary language id, sublang index) -> name
SUBLANGS = {
    (1, 1): "ARABIC_SAUDI_ARABIA",  # ARABIC
    (1, 2): "ARABIC_IRAQ",  # ARABIC
    (1, 3): "ARABIC_EGYPT",  # ARABIC
    (1, 4): "ARABIC_LIBYA",  # ARABIC
    (1, 5): "ARABIC_ALGERIA",  # ARABIC
    (1, 6): "ARABIC_MOROCCO",  # ARABIC
    (1, 7): "ARABIC_TUNISIA",  # ARABIC
    (1, 8): "ARABIC_OMAN",  # ARABIC
    (1, 9): "ARABIC_YEMEN",  # ARABIC
    (1, 10): "ARABIC_SYRIA",  # ARABIC
    (1, 11): "ARABIC_JORDAN",  # ARABIC
    (1, 12): "ARABIC_LEBANON",  # ARABIC
    (1, 13): "ARABIC_KUWAIT",  # ARABIC
    (1, 14): "ARABIC_UAE",  # ARABIC
    (1, 15): "ARABIC_BAHRAIN",  # ARABIC
    (1, 16): "ARABIC_QATAR",  # ARABIC
    (2, 1): "BULGARIAN_BULGARIA",  # BULGARIAN
    (3, 1): "CATALAN_CATALAN",  # CATALAN
    (3, 2): "VALENCIAN_VALENCIA",  # CATALAN
    (4, 1): "CHINESE_TRADITIONAL",  # CHINESE
    (4, 2): "CHINESE_SIMPLIFIED",  # CHINESE
    (4, 3): "CHINESE_HONGKONG",  # CHINESE
    (4, 4): "CHINESE_SINGAPORE",  # CHINESE
    (4, 5): "CHINESE_MACAU",  # CHINESE
    (5, 1): "CZECH_CZECH_REPUBLIC",  # CZECH
    (6, 1): "DANISH_DENMARK",  # DANISH
    (7, 1): "GERMAN",  # GERMAN
    (7, 2): "GERMAN_SWISS",  # GERMAN
    (7, 3): "GERMAN_AUSTRIAN",  # GERMAN
    (7, 4): "GERMAN_LUXEMBOURG",  # GERMAN
    (7, 5): "GERMAN_LIECHTENSTEIN",  # GERMAN
    (8, 1): "GREEK_GREECE",  # GREEK
    (9, 1): "ENGLISH_US",  # ENGLISH
    (9, 2): "ENGLISH_UK",  # ENGLISH
    (9, 3): "ENGLISH_AUS",  # ENGLISH
    (9, 4): "ENGLISH_CAN",  # ENGLISH
    (9, 5): "ENGLISH_NZ",  # ENGLISH
    (9, 6): "ENGLISH_IRELAND",  # ENGLISH
    (9, 7): "ENGLISH_SOUTH_AFRICA",  # ENGLISH
    (9, 8): "ENGLISH_JAMAICA",  # ENGLISH
    (9, 9): "ENGLISH_CARIBBEAN",  # ENGLISH
    (9, 10): "ENGLISH_BELIZE",  # ENGLISH
    (9, 11): "ENGLISH_TRINIDAD",  # ENGLISH
    (9, 12): "ENGLISH_ZIMBABWE",  # ENGLISH
    (9, 13): "ENGLISH_PHILIPPINES",  # ENGLISH
    (9, 16): "ENGLISH_INDIA",  # ENGLISH
    (9, 17): "ENGLISH_MALAYSIA",  # ENGLISH
    (9, 18): "ENGLISH_SINGAPORE",  # ENGLISH
    (10, 1): "SPANISH",  # SPANISH
    (10, 2): "SPANISH_MEXICAN",  # SPANISH
    (10, 3): "SPANISH_MODERN",  # SPANISH
    (10, 4): "SPANISH_GUATEMALA",  # SPANISH
    (10, 5): "SPANISH_COSTA_RICA",  # SPANISH
    (10, 6): "SPANISH_PANAMA",  # SPANISH
    (10, 7): "SPANISH_DOMINICAN_REPUBLIC",  # SPANISH
    (10, 8): "SPANISH_VENEZUELA",  # SPANISH
    (10, 9): "SPANISH_COLOMBIA",  # SPANISH
    (10, 10): "SPANISH_PERU",  # SPANISH
    (10, 11): "SPANISH_ARGENTINA",  # SPANISH
    (10, 12): "SPANISH_ECUADOR",  # SPANISH
    (10, 13): "SPANISH_CHILE",  # SPANISH
    (10, 14): "SPANISH_URUGUAY",  # SPANISH
    (10, 15): "SPANISH_PARAGUAY",  # SPANISH
    (10, 16): "SPANISH_BOLIVIA",  # SPANISH
    (10, 17): "SPANISH_EL_SALVADOR",  # SPANISH
    (10, 18): "SPANISH_HONDURAS",  # SPANISH
    (10, 19): "SPANISH_NICARAGUA",  # SPANISH
    (10, 20): "SPANISH_PUERTO_RICO",  # SPANISH
    (10, 21): "SPANISH_US",  # SPANISH
    (11, 1): "FINNISH_FINLAND",  # FINNISH
    (12, 1): "FRENCH",  # FRENCH
    (12, 2): "FRENCH_BELGIAN",  # FRENCH
    (12, 3): "FRENCH_CANADIAN",  # FRENCH
    (12, 4): "FRENCH_SWISS",  # FRENCH
    (12, 5): "FRENCH_LUXEMBOURG",  # FRENCH
    (12, 6): "FRENCH_MONACO",  # FRENCH
    (13, 1): "HEBREW_ISRAEL",  # HEBREW
    (14, 1): "HUNGARIAN_HUNGARY",  # HUNGARIAN
    (15, 1): "ICELANDIC_ICELAND",  # ICELANDIC
    (16, 1): "ITALIAN",  # ITALIAN
    (16, 2): "ITALIAN_SWISS",  # ITALIAN
    (17, 1): "JAPANESE_JAPAN",  # JAPANESE
    (18, 1): "KOREAN",  # KOREAN
    (19, 1): "DUTCH",  # DUTCH
    (19, 2): "DUTCH_BELGIAN",  # DUTCH
    (20, 1): "NORWEGIAN_BOKMAL",  # NORWEGIAN
    (20, 2): "NORWEGIAN_NYNORSK",  # NORWEGIAN
    (21, 1): "POLISH_POLAND",  # POLISH
    (22, 1): "PORTUGUESE_BRAZILIAN",  # PORTUGUESE
    (22, 2): "PORTUGUESE_PORTUGAL",  # PORTUGUESE
    (23, 1): "ROMANSH_SWITZERLAND",  # RHAETO_ROMANCE
    (24, 1): "ROMANIAN_ROMANIA",  # ROMANIAN
    (25, 1): "RUSSIAN_RUSSIA",  # RUSSIAN
    (26, 1): "CROATIAN_CROATIA",  # CROATIAN
    (26, 2): "SERBIAN_LATIN",  # CROATIAN
    (26, 3): "SERBIAN_CYRILLIC",  # CROATIAN
    (26, 4): "CROATIAN_BOSNIA_HERZEGOVINA_LATIN",  # CROATIAN
    (26, 5): "BOSNIAN_BOSNIA_HERZEGOVINA_LATIN",  # CROATIAN
    (26, 6): "SERBIAN_BOSNIA_HERZEGOVINA_LATIN",  # CROATIAN
    (26, 7): "SERBIAN_BOSNIA_HERZEGOVINA_CYRILLIC",  # CROATIAN
    (26, 8): "BOSNIAN_BOSNIA_HERZEGOVINA_CYRILLIC",  # CROATIAN
    (26, 9): "SERBIAN_SERBIA_LATIN",  # CROATIAN
    (26, 10): "SERBIAN_SERBIA_CYRILLIC",  # CROATIAN
    (26, 11): "SERBIAN_MONTENEGRO_LATIN",  # CROATIAN
    (26, 12): "SERBIAN_MONTENEGRO_CYRILLIC",  # CROATIAN
    (27, 1): "SLOVAK_SLOVAKIA",  # SLOVAK
    (28, 1): "ALBANIAN_ALBANIA",  # ALBANIAN
    (29, 1): "SWEDISH_SWEDEN",  # SWEDISH
    (29, 2): "SWEDISH_FINLAND",  # SWEDISH
    (30, 1): "THAI_THAILAND",  # THAI
    (31, 1): "TURKISH_TURKEY",  # TURKISH
    (32, 1): "URDU_PAKISTAN",  # URDU
    (32, 2): "URDU_INDIA",  # URDU
    (33, 1): "INDONESIAN_INDONESIA",  # INDONESIAN
    (34, 1): "UKRAINIAN_UKRAINE",  # UKRAINIAN
    (35, 1): "BELARUSIAN_BELARUS",  # BELARUSIAN
    (36, 1): "SLOVENIAN_SLOVENIA",  # SLOVENIAN
    (37, 1): "ESTONIAN_ESTONIA",  # ESTONIAN
    (38, 1): "LATVIAN_LATVIA",  # LATVIAN
    (39, 1): "LITHUANIAN_LITHUANIA",  # LITHUANIAN
    (40, 1): "TAJIK_TAJIKISTAN",  # MAORI
    (41, 1): "PERSIAN_IRAN",  # FARSI
    (42, 1): "VIETNAMESE_VIETNAM",  # VIETNAMESE
    (43, 1): "ARMENIAN_ARMENIA",  # ARMENIAN
    (44, 1): "AZERI_LATIN",  # AZERI
    (44, 2): "AZERI_CYRILLIC",  # AZERI
    (45, 1): "BASQUE_BASQUE",  # BASQUE
    (46, 1): "UPPER_SORBIAN_GERMANY",  # SORBIAN
    (46, 2): "LOWER_SORBIAN_GERMANY",  # SORBIAN
    (47, 1): "MACEDONIAN_MACEDONIA",  # MACEDONIAN
    (50, 1): "TSWANA_SOUTH_AFRICA",  # TSWANA
    (50, 2): "TSWANA_BOTSWANA",  # TSWANA
    (52, 1): "XHOSA_SOUTH_AFRICA",  # XHOSA
    (53, 1): "ZULU_SOUTH_AFRICA",  # ZULU
    (54, 1): "AFRIKAANS_SOUTH_AFRICA",  # AFRIKAANS
    (55, 1): "GEORGIAN_GEORGIA",  # GEORGIAN
    (56, 1): "FAEROESE_FAROE_ISLANDS",  # FAEROESE
    (57, 1): "HINDI_INDIA",  # HINDI
    (58, 1): "MALTESE_MALTA",  # MALTESE
    (59, 1): "SAMI_NORTHERN_NORWAY",  # SAMI
    (59, 2): "SAMI_NORTHERN_SWEDEN",  # SAMI
    (59, 3): "SAMI_NORTHERN_FINLAND",  # SAMI
    (59, 4): "SAMI_LULE_NORWAY",  # SAMI
    (59, 5): "SAMI_LULE_SWEDEN",  # SAMI
    (59, 6): "SAMI_SOUTHERN_NORWAY",  # SAMI
    (59, 7): "SAMI_SOUTHERN_SWEDEN",  # SAMI
    (59, 8): "SAMI_SKOLT_FINLAND",  # SAMI
    (59, 9): "SAMI_INARI_FINLAND",  # SAMI
    (60, 2): "IRISH_IRELAND",  # GAELIC
    (62, 1): "MALAY_MALAYSIA",  # MALAY
    (62, 2): "MALAY_BRUNEI_DARUSSALAM",  # MALAY
    (63, 1): "KAZAK_KAZAKHSTAN",  # KAZAK
    (64, 1): "KYRGYZ_KYRGYZSTAN",  # KYRGYZ
    (65, 1): "SWAHILI_KENYA",  # SWAHILI
    (66, 1): "TURKMEN_TURKMENISTAN",  # 0x42
    (67, 1): "UZBEK_LATIN",  # UZBEK
    (67, 2): "UZBEK_CYRILLIC",  # UZBEK
    (68, 1): "TATAR_RUSSIA",  # TATAR
    (69, 1): "BANGLA_INDIA",  # BANGLA
    (69, 2): "BANGLA_BANGLADESH",  # BANGLA
    (70, 1): "PUNJABI_INDIA",  # PUNJABI
    (70, 2): "PUNJABI_PAKISTAN",  # PUNJABI
    (71, 1): "GUJARATI_INDIA",  # GUJARATI
    (72, 1): "ODIA_INDIA",  # ORIYA
    (73, 1): "TAMIL_INDIA",  # TAMIL
    (73, 2): "TAMIL_SRI_LANKA",  # TAMIL
    (74, 1): "TELUGU_INDIA",  # TELUGU
    (75, 1): "KANNADA_INDIA",  # KANNADA
    (76, 1): "MALAYALAM_INDIA",  # MALAYALAM
    (77, 1): "ASSAMESE_INDIA",  # ASSAMESE
    (78, 1): "MARATHI_INDIA",  # MARATHI
    (79, 1): "SANSKRIT_INDIA",  # SANSKRIT
    (80, 1): "MONGOLIAN_CYRILLIC_MONGOLIA",  # MONGOLIAN
    (80, 2): "MONGOLIAN_PRC",  # MONGOLIAN
    (81, 1): "TIBETAN_PRC",  # 0x51
    (81, 2): "TIBETAN_BHUTAN",  # 0x51
    (82, 1): "WELSH_UNITED_KINGDOM",  # 0x52
    (83, 1): "KHMER_CAMBODIA",  # 0x53
    (84, 1): "LAO_LAO",  # 0x54
    (86, 1): "GALICIAN_GALICIAN",  # GALICIAN
    (87, 1): "KONKANI_INDIA",  # KONKANI
    (89, 1): "SINDHI_INDIA",  # SINDHI
    (89, 2): "SINDHI_AFGHANISTAN",  # SINDHI
    (90, 1): "SYRIAC",  # SYRIAC
    (91, 1): "SINHALESE_SRI_LANKA",  # 0x5b
    (92, 1): "CHEROKEE_CHEROKEE",  # 0x5c
    (93, 1): "INUKTITUT_CANADA",  # INUKTITUT
    (93, 2): "INUKTITUT_CANADA_LATIN",  # INUKTITUT
    (94, 1): "AMHARIC_ETHIOPIA",  # 0x5e
    (95, 2): "TAMAZIGHT_ALGERIA_LATIN",  # TAMAZIGHT
    (95, 4): "TAMAZIGHT_MOROCCO_TIFINAGH",  # TAMAZIGHT
    (96, 2): "KASHMIRI_INDIA",  # KASHMIRI
    (97, 1): "NEPALI_NEPAL",  # NEPALI
    (97, 2): "NEPALI_INDIA",  # NEPALI
    (98, 1): "FRISIAN_NETHERLANDS",  # 0x62
    (99, 1): "PASHTO_AFGHANISTAN",  # 0x63
    (100, 1): "FILIPINO_PHILIPPINES",  # 0x64
    (101, 1): "DIVEHI_MALDIVES",  # DIVEHI
    (103, 2): "FULAH_SENEGAL",  # PULAR
    (104, 1): "HAUSA_NIGERIA_LATIN",  # 0x68
    (106, 1): "YORUBA_NIGERIA",  # 0x6a
    (107, 1): "QUECHUA_BOLIVIA",  # QUECHUA
    (107, 2): "QUECHUA_ECUADOR",  # QUECHUA
    (107, 3): "QUECHUA_PERU",  # QUECHUA
    (108, 1): "SOTHO_NORTHERN_SOUTH_AFRICA",  # 0x6c
    (109, 1): "BASHKIR_RUSSIA",  # 0x6d
    (110, 1): "LUXEMBOURGISH_LUXEMBOURG",  # 0x6e
    (111, 1): "GREENLANDIC_GREENLAND",  # 0x6f
    (112, 1): "IGBO_NIGERIA",  # 0x70
    (115, 1): "TIGRINYA_ETHIOPIA",  # TIGRINYA
    (115, 2): "TIGRIGNA_ERITREA",  # TIGRINYA
    (117, 1): "HAWAIIAN_US",  # 0x75
    (120, 1): "YI_PRC",  # 0x78
    (122, 1): "MAPUDUNGUN_CHILE",  # 0x7a
    (124, 1): "MOHAWK_MOHAWK",  # 0x7c
    (126, 1): "BRETON_FRANCE",  # 0x7e
    (128, 1): "UIGHUR_PRC",  # 0x80
    (129, 1): "MAORI_NEW_ZEALAND",  # 0x81
    (130, 1): "OCCITAN_FRANCE",  # 0x82
    (131, 1): "CORSICAN_FRANCE",  # 0x83
    (132, 1): "ALSATIAN_FRANCE",  # 0x84
    (133, 1): "SAKHA_RUSSIA",  # 0x85
    (134, 1): "KICHE_GUATEMALA",  # 0x86
    (135, 1): "KINYARWANDA_RWANDA",  # 0x87
    (136, 1): "WOLOF_SENEGAL",  # 0x88
    (140, 1): "DARI_AFGHANISTAN",  # 0x8c
    (145, 1): "SCOTTISH_GAELIC",  # CORNISH
    (146, 1): "CENTRAL_KURDISH_IRAQ",  # WELSH
}

# Indexes with a generic, language-independent meaning, used when the pair is not in SUBLANGS
GENERIC_SUBLANGS = {
    0: "NEUTRAL",
    1: "DEFAULT",
    2: "SYS_DEFAULT",
    3: "CUSTOM_DEFAULT",
    4: "CUSTOM_UNSPECIFIED",
    5: "UI_CUSTOM_DEFAULT",
}


def sublang_pair_name(primary, sub):
    """Resolve a sublanguage name from an already-split (primary language, sublanguage) pair,
    as exposed by objects like lief.PE.ResourceIcon.

    Returns:
        str: the Windows SUBLANG constant name (e.g. "ENGLISH_US") when the
        (primary language, sublanguage) pair is documented, else the generic name for
        language-independent indexes (e.g. "NEUTRAL", "DEFAULT"), else the numeric
        sublanguage index as a string.
    """
    name = SUBLANGS.get((primary, sub))
    if name is not None:
        return name
    return GENERIC_SUBLANGS.get(sub, str(sub))


def sublang_name(lang_id):
    """Resolve the sublanguage name of a full 16-bit resource language identifier.

    Returns:
        str: same as sublang_pair_name(), for the identifier's primary language
        (low 10 bits) and sublanguage (next 6 bits).
    """
    return sublang_pair_name(lang_id & 0x3FF, (lang_id >> 10) & 0x3F)
