import packet from 'dns-packet';

declare module 'dns-packet' {
  interface Packet {
    rcode: string;
  }
}
