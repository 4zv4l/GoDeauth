package color

func ColorPrint(color string, str string) string {
  colorReset := "\033[0m"
  switch color {
  case "red":
  colorRed := "\033[31m"
  return colorRed + str + colorReset
  case "green":
  colorGreen := "\033[32m"
  return colorGreen + str + colorReset
  case "yellow":
  colorYellow := "\033[33m"
  return colorYellow + str + colorReset
  case "blue":
  colorBlue := "\033[34m"
  return colorBlue + str + colorReset
  case "purple":
  colorPurple := "\033[35m"
  return colorPurple + str + colorReset
  case "cyan":
  colorCyan := "\033[36m"
  return colorCyan + str + colorReset
  case "white":
  colorWhite := "\033[37m"
  return colorWhite + str + colorReset
  default:
  return str + colorReset
  }
}

