from flask import Flask, render_template
from collections import defaultdict

app = Flask(__name__)

@app.route("/")
def home():
    return "Login Attack Detector is running!"

@app.route("/analyze")
def analyze_log():
    with open("log.txt", "r") as file:
        lines = file.readlines()

    user_failures = defaultdict(int)
    user_logs = defaultdict(list)
    brute_force_users = []
    failures_per_user = defaultdict(int)

    for line in lines:
        if "login attempt" in line and "user:" in line:
            parts = line.strip().split("user:")
            if len(parts) > 1:
                user_info = parts[1].strip().split(" ")[0]
                user_logs[user_info].append(line.strip())

                if "failed" in line:
                    user_failures[user_info] += 1
                    failures_per_user[user_info] += 1

                    if user_failures[user_info] >= 3:
                        brute_force_users.append({
                            "user": user_info,
                            "message": "Possible brute force attack",
                            "log": user_logs[user_info]
                        })
                else:
                    user_failures[user_info] = 0  # reset on success

    # נשלח גם את רשימת המשתמשים והכמות כשלונות
    return render_template("results.html", 
                           attacks=brute_force_users,
                           users=list(failures_per_user.keys()),
                           counts=list(failures_per_user.values()))

if __name__ == "__main__":
    app.run(debug=True)
