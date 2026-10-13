import { DOMParser } from '@xmldom/xmldom';
import xpath from 'xpath';

/** DOM node/document types produced by `@xmldom/xmldom`. */
export type XmlDocument = ReturnType<DOMParser['parseFromString']>;
export type XmlNode = NonNullable<XmlDocument['documentElement']>;

export function parseXml(xml: string): XmlDocument {
  return new DOMParser({
    onError: (level, msg) => {
      if (level === 'fatalError') throw new Error(msg);
    },
  }).parseFromString(xml, 'text/xml');
}

/** Evaluates an XPath expression and always returns an array of nodes. */
export function selectNodes(expression: string, node: unknown): XmlNode[] {
  const result = xpath.select(expression, node as Node);
  return Array.isArray(result) ? (result as unknown as XmlNode[]) : [];
}
