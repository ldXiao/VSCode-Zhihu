import * as MarkdownIt from "markdown-it";
import * as markdown_it_zhihu from "markdown-it-zhihu";

/**
 * Markdown -> Zhihu-flavoured HTML, matching the renderer the VSCode extension
 * uses to publish (extension.ts). Zhihu expects tables wrapped in its own
 * `data-draft` markup rather than a plain `<thead>/<tbody>`.
 */
let parser: MarkdownIt | null = null;

function getParser(): MarkdownIt {
	if (parser) return parser;
	const md = new MarkdownIt({ html: true }).use(markdown_it_zhihu);
	md.renderer.rules.table_open = () =>
		'<table data-draft-node="block" data-draft-type="table" data-size="normal" data-row-style="striped"><tbody>';
	md.renderer.rules.table_close = () => "</tbody></table>";
	md.renderer.rules.thead_open = () => "";
	md.renderer.rules.thead_close = () => "";
	md.renderer.rules.tbody_open = () => "";
	md.renderer.rules.tbody_close = () => "";
	parser = md;
	return md;
}

/** Render Markdown source to the HTML string Zhihu's publish APIs expect. */
export function renderZhihuHtml(markdown: string): string {
	return getParser().render(markdown);
}
