int increment_bounded(unsigned int value) {
    return value < 100 ? (int)(value + 1) : 0;
}
