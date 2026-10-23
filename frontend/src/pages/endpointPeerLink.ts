import {
  endpointUrl,
  type EndpointSelection,
} from "../data/endpointInvestigation";

export const peerEndpointUrl = (
  selection: Pick<EndpointSelection, "scope" | "start" | "end">,
  peer: string,
  pathname: string,
) =>
  endpointUrl(
    {
      address: peer,
      scope: selection.scope,
      start: selection.start,
      end: selection.end,
    },
    pathname,
  );
