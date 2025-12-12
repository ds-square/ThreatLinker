from django import template
from data.models import CAPEC

register = template.Library()

@register.filter(name='get_item_by_id')
def get_item_by_id(queryset, item_id):
    """
    Questo filtro personalizzato prende un queryset (CAPEC objects) e un ID,
    quindi restituisce l'oggetto corrispondente all'ID.
    """
    try:
        # Aggiungi una gestione per l'ID in formato stringa se necessario
        return queryset.get(id=item_id)
    except CAPEC.DoesNotExist:
        return None

@register.filter(name='get_dict_value')
def get_dict_value(dictionary, key):
    """Restituisce il valore del dizionario dato un nome di chiave, gestendo eventuali errori."""
    if isinstance(dictionary, dict):
        return dictionary.get(key)
    return None  # O un valore predefinito, come una stringa "N/A" se il tipo non è dizionario
