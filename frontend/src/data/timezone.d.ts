declare module "@splunk/moment/convertSplunkTimezone" {
  export default function convert(
    value: string,
    name: string,
  ): { name: string; abbrs: string[]; offsets: number[]; untils: number[] };
}
