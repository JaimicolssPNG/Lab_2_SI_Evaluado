def FuncionDH(Base, Exponente, Modulo):
    x = 1
    y = Base % Modulo
    b = Exponente
    while (b>0):
        if ((b % 2) == 0):
            y = (y * y) % Modulo
            b = b/2
        else:
            x = (x * y) % Modulo
            b-=1
    return x
