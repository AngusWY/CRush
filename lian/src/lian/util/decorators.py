
def static_vars(**kwargs):

    def decorate(func):
        for k, v in kwargs.items():

            value = v() if callable(v) else v
            setattr(func,k,value)
        return func
    return decorate
