from github import Github

g = Github("1bd500a3face4b51a9a88f1e92626a5467c226fe")

for repo in g.get_user().get_repos():
    print(repo.name)