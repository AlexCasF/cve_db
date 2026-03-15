# AI Test Prompts

This file contains test prompts for the AI query feature in `query.py` and the Streamlit chat in `ui.py`.

Use these prompts to check:

- simple natural-language-to-SQL conversion
- multi-table joins across `cves`, `vendors`, `products`, and `cve_products`
- ordering, limits, and date-based filtering
- aggregation and grouping queries
- robustness against vague or ambiguous questions
- whether the app asks a clarification question when it should

Notes:

- Some prompts may return zero rows depending on the current contents of `cve.db`.
- That is still useful: the goal is to test SQL generation quality and safety, not only data coverage.
- Clarification prompts are included on purpose. For those, the best result is usually a follow-up question instead of immediate SQL.

## Block 1: Basic Lookup and Low Complexity

These should produce straightforward `SELECT` queries with simple filters, ordering, or limits.

1. `show me the latest 5 CVEs`
2. `find CVE-2024-3094`
3. `show 10 critical vulnerabilities`
4. `list CVEs above 9.0`
5. `show the newest microsoft bugs`
6. `find recent linux vulnerabilities`

## Block 2: Medium Complexity Filters and Joins

These should encourage joins through vendors and products, plus combined filtering conditions.

7. `show me the 10 latest microsoft issues above 8.0`
8. `list adobe vulnerabilities published this year`
9. `show oracle bugs with CVSS score between 7.0 and 9.0`
10. `find chrome-related CVEs from the last 30 days`
11. `show the newest windows vulnerabilities with a high severity score`
12. `show recent vulnerabilities affecting vmware products`

## Block 3: Broad Matching and Search Semantics

These test whether the planner searches broadly across CVE ID, description, vendor, and product names instead of relying on exact matches.

13. `show me the latest openclaw bug`
14. `find the newest linux bug above 8`
15. `show 20 issues related to exchange server`
16. `find vulnerabilities mentioning remote code execution in microsoft products`
17. `show the newest bugs related to authentication bypass`
18. `list recent CVEs tied to kernel memory corruption`

## Block 4: Aggregation, Grouping, and Trend Queries

These should push the model toward `COUNT`, `AVG`, `GROUP BY`, sorting by aggregates, and possibly distinct counting.

19. `which 10 vendors have the most CVEs`
20. `what is the average CVSS score for adobe vulnerabilities`
21. `show me the number of CVEs per severity`
22. `which products appear in the most vulnerabilities`
23. `count how many microsoft CVEs are above 8.0`
24. `show the top 5 vendors by number of critical issues`

## Block 5: High Complexity Analyst-Style Questions

These are intentionally more complex and may result in longer SQL with joins, grouping, sorting, and multiple conditions.

25. `show the 5 vendors with the highest average CVSS among vendors that have at least 10 CVEs`
26. `which products have more than 3 CVEs above 9.0`
27. `show me the latest 10 CVEs for vendors that also have at least one critical issue`
28. `find vendors whose average CVSS is above 7.5 and sort them by total CVE count`
29. `show the newest 15 vulnerabilities affecting products from vendors with more than 50 CVEs`
30. `which vendor has the biggest gap between total CVEs and critical CVEs`

## Block 6: Bonus Multi-Turn Clarification Tests

These are useful for testing the multi-turn flow in `run_query()` or the Streamlit chat. These are bonus prompts beyond the 30 core examples above.

### Pair A: Severity Threshold

First prompt:

`show me the bad ones`

Possible follow-up answer:

`I mean CVEs with a CVSS score of 9.0 or higher.`

### Pair B: Time Window

First prompt:

`show me recent microsoft vulnerabilities`

Possible follow-up answer:

`By recent I mean the last 30 days.`

### Pair C: Scope of "Worst"

First prompt:

`what are the worst adobe bugs`

Possible follow-up answer:

`Show the 10 highest CVSS results.`

### Pair D: Product Versus Vendor Ambiguity

First prompt:

`show me the latest office issues`

Possible follow-up answer:

`I mean Microsoft Office, not office software in general.`

## Suggested Testing Order

If you want a practical sequence instead of random testing:

1. Start with prompts 1 to 6
2. Move to prompts 7 to 12
3. Try prompts 19 to 24
4. Finish with prompts 25 to 30 for the hardest SQL generation
5. Then run the bonus multi-turn clarification tests
