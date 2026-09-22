"""脱敏核心算法的纯单元测试。"""
from app.redaction import AUTO, MANUAL, InputSpan, redact, resolve_spans, assign_placeholders


def _span(start, end, priority, category, ordinal, source=MANUAL, rule_id=None):
    return InputSpan(start, end, priority, category, ordinal, source=source, rule_id=rule_id)


def test_basic_stable_placeholders():
    text = "张三向李四借款"
    result = redact(
        text,
        [_span(0, 2, 0, "PERSON", 0), _span(3, 5, 0, "PERSON", 1)],
    )
    assert result.redacted_text == "{{PERSON:01}}向{{PERSON:02}}借款"
    assert all(s.kept for s in result.spans)


def test_same_category_value_reuses_placeholder():
    text = "张三认识张三"
    result = redact(
        text,
        [_span(0, 2, 0, "PERSON", 0), _span(4, 6, 0, "PERSON", 1)],
    )
    assert result.redacted_text == "{{PERSON:01}}认识{{PERSON:01}}"
    assert result.spans[0].placeholder == result.spans[1].placeholder


def test_overlapping_higher_priority_wins():
    # 低优先级大片段 vs 高优先级子片段
    text = "甲方：北京某某科技有限公司"
    result = redact(
        text,
        [
            _span(3, 13, 1, "ORG", 0),    # 北京某某科技有限公司 高优先级
            _span(0, 13, 0, "OTHER", 1),  # 整行 低优先级，重叠丢弃
        ]
    )
    assert result.spans[0].kept
    assert result.spans[0].category == "ORG"
    assert not result.spans[1].kept
    assert result.spans[1].drop_reason == "overlaps_higher_priority"
    assert result.redacted_text == "甲方：{{ORG:01}}"


def test_equal_priority_first_come_first_served():
    text = "abcdef"
    result = redact(
        text,
        [_span(0, 3, 0, "A", 0), _span(2, 5, 0, "B", 1)],
    )
    assert result.spans[0].kept
    assert not result.spans[1].kept


def test_unicode_codepoint_offsets():
    # 含 emoji 与中文，按码位计数
    text = "合同🎉甲方张三"
    assert text[3:5] == "甲方"
    result = redact(text, [_span(5, 7, 0, "PERSON", 0)])
    assert result.redacted_text == "合同🎉甲方{{PERSON:01}}"


def test_nested_spans_both_kept_when_not_overlapping_higher_priority():
    # 两个相邻（非重叠）片段均保留
    text = "0123456789"
    result = redact(text, [_span(0, 2, 5, "A", 0), _span(2, 4, 1, "B", 1)])
    assert result.redacted_text == "{{A:01}}{{B:01}}456789"


def test_resolution_is_deterministic_regardless_of_input_order():
    text = "abcdef"
    low_first = redact(text, [_span(2, 5, 0, "B", 0), _span(0, 3, 5, "A", 1)])
    high_first = redact(text, [_span(0, 3, 5, "A", 0), _span(2, 5, 0, "B", 1)])
    assert low_first.redacted_text == high_first.redacted_text == "{{A:01}}def"


def test_assign_placeholders_width_grows():
    spans = resolve_spans(
        "012345678901",
        [
            _span(0, 1, 0, "X", 0),
            _span(1, 2, 0, "X", 1),
            _span(2, 3, 0, "X", 2),
            _span(3, 4, 0, "X", 3),
            _span(4, 5, 0, "X", 4),
            _span(5, 6, 0, "X", 5),
            _span(6, 7, 0, "X", 6),
            _span(7, 8, 0, "X", 7),
            _span(8, 9, 0, "X", 8),
            _span(9, 10, 0, "X", 9),
        ],
    )
    assign_placeholders(spans)
    assert spans[0].placeholder == "{{X:01}}"
    assert spans[9].placeholder == "{{X:10}}"


def test_manual_wins_when_priority_offsets_length_all_equal():
    text = "abcdef"
    # 同起止、同长度、同优先级；ordinal 让自动片段“先到”，仍应由人工片段胜出
    result = redact(
        text,
        [
            _span(0, 3, 0, "AUTO", 0, source=AUTO, rule_id="r1"),
            _span(0, 3, 0, "MANUAL", 1),
        ],
    )
    kept = [s for s in result.spans if s.kept]
    dropped = [s for s in result.spans if not s.kept]
    assert len(kept) == 1 and kept[0].category == "MANUAL"
    assert kept[0].source == MANUAL and kept[0].rule_id is None
    assert len(dropped) == 1 and dropped[0].source == AUTO
    assert dropped[0].rule_id == "r1"
    assert dropped[0].drop_reason == "overlaps_higher_priority"
    assert result.redacted_text == "{{MANUAL:01}}def"


def test_higher_priority_auto_beats_manual():
    text = "abcdef"
    result = redact(
        text,
        [
            _span(0, 3, 5, "AUTO", 0, source=AUTO, rule_id="r1"),
            _span(0, 3, 0, "MANUAL", 1),
        ],
    )
    kept = [s for s in result.spans if s.kept]
    assert kept[0].category == "AUTO" and kept[0].rule_id == "r1"


def test_auto_span_labels_preserved_through_placeholder_assignment():
    text = "张三张三"
    result = redact(text, [_span(0, 2, 0, "PERSON", 0, source=AUTO, rule_id="p")])
    assert result.redacted_text == "{{PERSON:01}}张三"
    assert result.spans[0].source == AUTO and result.spans[0].rule_id == "p"


# ---------- 片段冲突溯源：fragment_id / decision_rank / blocked_by ----------


def test_fragment_ids_follow_merged_original_order():
    # ordinal：人工 0、1，自动 2、3 追加其后；ID 只认原始顺序，与决策先后无关
    text = "abcdef"
    result = redact(
        text,
        [
            _span(0, 1, 0, "A", 0),
            _span(1, 2, 0, "A", 1),
            _span(2, 3, 5, "A", 2, source=AUTO, rule_id="r1"),
            _span(3, 4, 5, "A", 3, source=AUTO, rule_id="r1"),
        ],
    )
    assert [s.fragment_id for s in result.spans] == [
        "frag-0001",
        "frag-0002",
        "frag-0003",
        "frag-0004",
    ]
    # 高优先级自动片段先落位（rank 1、2），但 ID 仍是其原始顺序号
    by_id = {s.fragment_id: s for s in result.spans}
    assert by_id["frag-0003"].decision_rank == 1
    assert by_id["frag-0004"].decision_rank == 2
    assert {s.decision_rank for s in result.spans} == {1, 2, 3, 4}
    assert all(s.kept and s.blocked_by_fragment_id is None for s in result.spans)


def test_exact_duplicate_candidates_get_distinct_ids():
    text = "abcdef"
    result = redact(
        text,
        [
            _span(0, 3, 0, "DUP", 0),
            _span(0, 3, 0, "DUP", 1),  # 起止、优先级、类别、原文完全相同
        ],
    )
    ids = [s.fragment_id for s in result.spans]
    assert ids == ["frag-0001", "frag-0002"]
    kept, dropped = result.spans
    assert kept.kept and kept.blocked_by_fragment_id is None
    assert not dropped.kept
    assert dropped.blocked_by_fragment_id == "frag-0001"
    assert dropped.decision_rank == 2
    assert dropped.drop_reason == "overlaps_higher_priority"


def test_equal_priority_blocked_by_first_placed():
    text = "abcdef"
    result = redact(
        text,
        [
            _span(0, 3, 0, "A", 0),
            _span(2, 5, 0, "B", 1),
        ],
    )
    first, second = result.spans
    assert first.kept and first.decision_rank == 1
    assert not second.kept and second.decision_rank == 2
    assert second.blocked_by_fragment_id == first.fragment_id


def test_blocker_is_decision_earliest_not_earliest_start():
    # 低优先级大跨度同时压过两个已保留区间：
    # 决策最先的是高优先级但 start 更靠后的片段，阻断者必须指向它
    text = "0123456789"
    result = redact(
        text,
        [
            _span(0, 5, 8, "EARLY_START", 0),   # rank 2
            _span(8, 10, 9, "LATE_START", 1),   # rank 1（优先级最高）
            _span(0, 10, 1, "BIG", 2),          # 与两者都相交
        ],
    )
    by_id = {s.fragment_id: s for s in result.spans}
    late = next(s for s in result.spans if s.category == "LATE_START")
    early = next(s for s in result.spans if s.category == "EARLY_START")
    big = next(s for s in result.spans if s.category == "BIG")
    assert late.decision_rank == 1 and early.decision_rank == 2
    assert not big.kept
    assert big.blocked_by_fragment_id == late.fragment_id


def test_dropped_span_does_not_block_later_candidate():
    # 中优先级大跨度先被高优先级片段拒绝；更低优先级的同位置候选也只能被
    # 已落位的高优先级片段阻断，而不是那个先判定却被丢弃的片段
    text = "0123456789"
    result = redact(
        text,
        [
            _span(2, 3, 9, "TOP", 0),    # rank 1 保留
            _span(0, 5, 5, "MID", 1),    # rank 2 丢弃
            _span(0, 5, 1, "LOW", 2),    # rank 3 丢弃
        ],
    )
    top, mid, low = result.spans
    assert top.kept
    assert not mid.kept and mid.blocked_by_fragment_id == top.fragment_id
    assert not low.kept and low.blocked_by_fragment_id == top.fragment_id


def test_candidate_spanning_multiple_kept_intervals():
    text = "0123456789"
    result = redact(
        text,
        [
            _span(0, 2, 5, "A", 0),    # rank 1 保留
            _span(5, 7, 5, "B", 1),    # rank 2 保留
            _span(0, 10, 0, "BIG", 2), # rank 3，跨越两个保留区间
        ],
    )
    a, b, big = result.spans
    assert a.kept and b.kept
    assert not big.kept
    # 两个已落位片段都相交，按决策先后取 rank 最小者
    assert big.blocked_by_fragment_id == a.fragment_id


def test_blocked_by_across_sources():
    # 同优先级同位置：人工先落位（决胜规则），自动片段被人工阻断
    text = "abcdef"
    result = redact(
        text,
        [
            _span(0, 3, 5, "MANUAL_TAG", 0),
            _span(0, 3, 5, "AUTO_TAG", 1, source=AUTO, rule_id="r"),
        ],
    )
    manual, auto = result.spans
    assert manual.kept
    assert not auto.kept
    assert auto.blocked_by_fragment_id == manual.fragment_id

    # 自动优先级更高时，人工片段被自动片段阻断
    result2 = redact(
        text,
        [
            _span(0, 3, 5, "MANUAL_TAG", 0),
            _span(0, 3, 9, "AUTO_TAG", 1, source=AUTO, rule_id="r"),
        ],
    )
    manual2, auto2 = result2.spans
    assert auto2.kept
    assert not manual2.kept
    assert manual2.blocked_by_fragment_id == auto2.fragment_id
