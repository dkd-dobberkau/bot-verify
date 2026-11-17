# bot-verify

Answers one question for website operators: **is this request really from the
bot it claims to be?**

A User-Agent string is free text. Anyone can call themselves GPTBot or
Googlebot. Most bot operators publish how to check the claim (an IP list or a
reverse-DNS suffix), but every operator does it differently, in a different
place and format. bot-verify collects those published methods and answers the
question for a given IP and bot name, for example over DNS, the way spam
blocklists are queried.

Status: idea, nothing built yet. See [docs/idea.md](docs/idea.md).

Spun off from [goodbot-badbot.com](https://goodbot-badbot.com), which measures
robots.txt compliance and keeps a catalog of what operators say about their bots
(https://goodbot-badbot.com/bots).
