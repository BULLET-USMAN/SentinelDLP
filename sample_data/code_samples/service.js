function calculateCheckDigit(value) {
  return value.split("").reduce((acc, c) => acc + c.charCodeAt(0), 0) % 10;
}
module.exports = { calculateCheckDigit };
