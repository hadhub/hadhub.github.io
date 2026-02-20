---
title: "Because reading JSON at 2 a.m. is a no-go."
date: 2026-02-20
draft: false
author: "Hadzah"
tags: ["tools", "research"]
description: "From Sarif to TODOLIST"
---

## What is SARIF?

SARIF (Static Analysis Results Interchange Format) is a standardized JSON format used by static analysis tools to report their findings. Tools like **semgrep** and **opengrep** can output their results in SARIF, making it possible to process and visualize findings from different scanners in a unified way.

The problem? SARIF files are dense, deeply nested JSON. Scrolling through hundreds of findings in a raw JSON file or even in VSCode gets painful fast, especially when you need to triage, annotate, and track the status of each finding across a full audit.

## Why this tool?

When I first became interested in code review, I came across a video by [noraj](https://www.youtube.com/watch?v=k99ml1v6FmA) explaining how to use semgrep to extract a sarif file and read it using vscode. I thought it was a smart idea and wanted to explore it further with my friend Claude Code, who immediately understood the concept. :))))

{{< figure src="img/readsarifat3am.png" alt="" align="center" width="20%" >}}

## The idea

Instead of fighting with raw JSON, I wanted a proper web interface that turns SARIF output into an actionable todo list, something where you can drag-and-drop your file, browse findings visually, and track your progress through an audit.

The main dashboard gives you a sortable, filterable list of all findings with their severity, status, and source location:

{{< figure src="img/dark_mod.png" align="center" >}}

A graph view provides visual representations of rule information, code flows from source to sink, and finding locations:

{{< figure src="img/dark_modgraph.png" align="center" >}}

A light mode is also available for those who prefer it.

## Features

- **SARIF file upload** drag-and-drop support with automatic parsing
- **Finding management** browse, filter, and search findings by severity, status, rule ID, file path, message, or code snippet
- **Status tracking** track findings through their lifecycle: New, Confirmed, False Positive, Mitigated, Accepted Risk
- **Annotations** add notes to individual findings for documentation and collaboration
- **SVG visualizations** generated graphs showing rule information, code flows (source to sink), and locations
- **Bulk operations** update the status of multiple findings at once
- **SARIF export** export findings back to SARIF format with embedded review status and notes
- **Multi-project support** manage multiple SARIF uploads as separate projects

## Result

At the time of writing this article, sarif2web is available on my GitHub: [sarif2web](https://github.com/hadhub/sarif2web)

You can deploy it via Docker and import sarif files. Each time you edit the status of a finding, it is stored in a MongoDB database so that you can return to it later without having to re-sort.

## What's next?

This is just the beginning. Here are some ideas I'm exploring:

- Support for additional static analysis formats beyond SARIF
- Link to the code base that triggered the alert
- Markdown/PDF export

The tool is open source and built to evolve. If you have ideas, feedback, or want to contribute, feel free to reach out on Discord (**hadzah**) or open a pull request on the repo.
