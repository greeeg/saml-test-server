// Ported from mcguinness/node-samlp (MIT, see ./LICENSE).
import { DOMParser, XMLSerializer } from '@xmldom/xmldom';

const whitespace = /^\s+$/;

type XmlNode = ReturnType<DOMParser['parseFromString']>['firstChild'];

function removeEmptyNodes(node: NonNullable<XmlNode>): void {
  for (let i = 0; i < node.childNodes.length; i++) {
    const current = node.childNodes[i];
    if (current.nodeType === 3 && whitespace.test(current.nodeValue ?? '')) {
      node.removeChild(current);
      i--;
    } else if (current.nodeType === 1) {
      removeEmptyNodes(current);
    }
  }
}

/** Removes whitespace-only text nodes and re-serializes the document. */
export function trimXml(xml: string): string {
  const dom = new DOMParser().parseFromString(xml, 'text/xml');
  removeEmptyNodes(dom as NonNullable<XmlNode>);
  return new XMLSerializer().serializeToString(dom);
}
