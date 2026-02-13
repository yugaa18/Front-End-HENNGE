let userScore = 0;
let compScore = 0;

function play(userChoice) {
    const choices = ["rock", "paper", "scissors"];
    const compChoice = choices[Math.floor(Math.random() * 3)];

    let resultText = "";

    if (userChoice === compChoice) {
        resultText = "It's a Draw! 🤝";
    } 
    else if (
        (userChoice === "rock" && compChoice === "scissors") ||
        (userChoice === "paper" && compChoice === "rock") ||
        (userChoice === "scissors" && compChoice === "paper")
    ) {
        userScore++;
        resultText = "You Win! 🎉";
    } 
    else {
        compScore++;
        resultText = "Computer Wins! 😢";
    }

    document.getElementById("result").innerHTML =
        "Computer chose: " + compChoice + "<br>" + resultText;

    document.getElementById("userScore").innerText = userScore;
    document.getElementById("compScore").innerText = compScore;
}
