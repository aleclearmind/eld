static int counter = 42;
extern int your();

int asdomare() {
    your();
    return counter++;
}
