from core.preprocessing.text_cleaner import TextCleaner

def preprocess_text(sentence, options):
    """
    Preprocessa il testo utilizzando il cleaner con le opzioni specificate.
    :param sentence: Frase da preprocessare.
    :param options: Dizionario con le opzioni di preprocessing (es. lowercase, remove_punctuation).
    :return: Testo preprocessato.
    """
    # Istanzia TextCleaner con le opzioni specificate
    cleaner = TextCleaner(
        lowercase=options.get('lowercase', True),
        remove_space_newline=options.get('remove_space_newline', True),
        remove_punctuation=options.get('remove_punctuation', False),
        remove_digits=options.get('remove_digits', False),
        remove_links=options.get('remove_links', False),
        remove_dates=options.get('remove_dates', False),
        remove_special_characters=options.get('remove_special_characters', False),
        expand_contractions=options.get('expand_contractions', False),
        genitive=options.get('genitive', False),
        remove_file_names=options.get('remove_file_names', False),
        remove_stop_words=options.get('remove_stop_words', False),
        remove_versions=options.get('remove_versions', True),
        lemmatize=options.get('lemmatize', False)
    )

    # Esegui il cleaning del testo
    return cleaner.clean_text(sentence)
