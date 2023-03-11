class InReplyToNotFound(Exception):
    def __init__(self, message="No In-Reply-To header."):
        self.message = message


class TooBigFile(Exception):
    def __init__(self, message="The attachment size larger than 10Mb"):
        self.message = message


class DomainIdentityException(Exception):
    def __init__(self, message="Created the domain unsuccessfully"):
        self.message = message
