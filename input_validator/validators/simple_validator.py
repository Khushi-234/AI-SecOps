# simple_validator.py
"""SimpleValidator mixin providing basic helper methods for validators.

Validators can inherit from :class:`SimpleValidator` to get access to common
utility methods without affecting the abstract ``BaseValidator`` hierarchy.
"""

from typing import Any, Dict


class SimpleValidator:
    """Mixin offering lightweight helpers.

    Currently provides a ``get_data`` method to retrieve the raw input data
    from a :class:`~input_validator.context.ValidationContext`.
    Extend this mixin with additional shared helpers as needed.
    """

    def get_data(self, context) -> Dict[str, Any]:
        """Return the underlying data dictionary from the validation context.
        """
        return getattr(context, "data", {})
