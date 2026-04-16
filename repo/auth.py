def login_required(fn):
    def wrapped(*args, **kwargs):
        return fn(*args, **kwargs)

    return wrapped


def admin_required(fn):
    def wrapped(*args, **kwargs):
        return fn(*args, **kwargs)

    return wrapped

