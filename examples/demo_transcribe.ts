/**
 * Demo CLI tool that gets transcription for an audio file using
 * the Transcribe Streaming API (HTTP/2 interface).
 */

import { connect } from 'http2'

import { signRequest, SignedRequest } from '../src/http'
import { encodeEvent, decodeEvent, MIME_TYPE } from '../src/events'
import { signEvent, PAYLOAD_EVENT } from '../src/events_sign'

import { readFileSync, writeFileSync } from 'fs'
import { promisify, inspect } from 'util'
const delay = promisify(setTimeout)

const accessKey = process.env.AWS_ACCESS_KEY_ID!
const secretKey = process.env.AWS_SECRET_ACCESS_KEY!
const args = process.argv.slice(2)
if (!accessKey || !secretKey || args.length !== 2) {
    console.error(`Usage: demo_transcribe.js <region> <file.wav> <out.json>`)
    console.error('Please make sure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set')
    console.error('For now, make sure the .wav file is 48000 Hz, 16-bit, mono')
    process.exit(1)
}

const [ region, audioFile, eventsFile ] = args
const input = readFileSync(audioFile)

console.log('Connecting to API...')
connect(`https://transcribestreaming.${region}.amazonaws.com`, session => {
    console.log('Starting transcription session...')
    const request: SignedRequest = {
        method: 'POST',
        url: {
            host: `transcribestreaming.${region}.amazonaws.com`,
            pathname: '/stream-transcription',
        },
        headers: {
            'content-type': MIME_TYPE,
            'x-amz-target': 'com.amazonaws.transcribe.Transcribe.StartStreamTranscription',
            'x-amzn-transcribe-language-code': 'es-US',
            'x-amzn-transcribe-media-encoding': 'pcm',
            'x-amzn-transcribe-sample-rate': 48000,
        },
        body: { hash: PAYLOAD_EVENT },
    }
    // FIXME: what happens with hosts with uppercase chars, how does node send them?
    //        when does node add port? should toRequestOptions add host header if not present, and separate host into hostname and port?
    // Is x-amz-content-sha256 needed? what happens if we set hash to empty_hash?
    // Does query signing work?
    // FIXME: have a maximum frame size
    const result = signRequest({ accessKey, secretKey }, request,
        { set: true, setContentHash: true })
    const stream = session.request({
        ...request.headers,
        ':method': request.method, // only if provided
        ':authority': (request.url as any).host, // only if host header not present
        ':path': (request.url as any).pathname, // add searchParams
    })

    stream.on('response', async response => {
        console.log('Received response:', { ...response })
        if (response[':status'] !== 200) {
            stream.on('end', () => process.exit(1)).pipe(process.stdout)
            return
        }
        if (response['content-type'] !== MIME_TYPE) {
            throw new Error('Invalid content-type received')
        }
        
        let lastSignature = result.signature.toString('hex')
        function sendEvent(event: Buffer = Buffer.alloc(0)) {
            const x = signEvent(lastSignature, result.credentials, {}, event)
            stream.write(encodeEvent(x.params, event))
            lastSignature = x.signature.toString('hex')
        }
        function sendAudio(chunk: Buffer = Buffer.alloc(0)) {
            sendEvent(encodeEvent({
                ':content-type': { type: 'string', data: 'application/octet-stream' },
                ':event-type': { type: 'string', data: 'AudioEvent' },
                ':message-type': { type: 'string', data: 'event' },
            }, chunk))
        }

        const sendStart = Date.now()
        const events: any[] = []
        let i = 0, chunkSize = 8 * 1024

        stream.on('data', chunk => {
            const { headers, data } = decodeEvent(chunk)
            const pdata = headers[':content-type'] && headers[':content-type'].data === 'application/json' ? JSON.parse(data.toString()) : data.toString()
            events.push({ when: Date.now() - sendStart, headers: headers, data: pdata })
            if (headers[':event-type'] && headers[':event-type'].data === 'TranscriptEvent') {
                const event = pdata as TranscriptEvent
                if (event.Transcript.Results.length === 1 && event.Transcript.Results[0].Alternatives.length) {
                    const result = event.Transcript.Results[0]
                    const partial = result.IsPartial
                    const id = result.ResultId.substr(0, 5)
                    const text = result.Alternatives[0].Transcript
                    const CSI = '\u001b['
                    process.stdout.write(`\r${CSI}J${CSI}3${partial ? 4 : 9}m${id}: ${text}${partial ? '' : '\n'}`)
                }
                /*console.log(event.Transcript.Results.map(result => {
                    const fmtTime = (x: number) => `${x}`
                    const timeTag = `${fmtTime(result.StartTime)} - ${fmtTime(result.EndTime)}`
                    return ` - ${result.ResultId.substr(0, 5)} (${timeTag}${result.IsPartial ? '' : ', NP'}): ${inspect(result.Alternatives.map(a => a.Transcript), { colors: true })}`
                }).join('\n'))*/
            } else {
                console.log('Received event:', headers, 'and data:', inspect(pdata, { depth: 9, colors: true }))
            }
        })

        while (i < input.length) {
            sendAudio(input.slice(i, i += chunkSize))
            await delay(chunkSize / (48000*2) * 1000)
        }

        // Send final chunk
        sendEvent()
        stream.end()

        stream.on('end', () => {
            session.close()
            writeFileSync(eventsFile, JSON.stringify(events) + '\n')
        })
    })
})



/** Represents a set of transcription results from the server to the client. It contains one or more segments of the transcription. */
export interface TranscriptEvent {
    /** The transcription of the audio stream. The transcription is composed of all of the items in the results list. */
    Transcript: Transcript
}

/** The transcription in a `TranscriptionEvent` */
export interface Transcript {
    /** [[Result]] objects that contain the results of transcribing a portion of the input audio stream. The array can be empty. */
    Results: Result[]
}

/** The result of transcribing a portion of the input audio stream. */
export interface Result {
    /** A unique identifier for the result. */
    ResultId: string
    /** The offset in milliseconds from the beginning of the audio stream to the beginning of the result. */
    StartTime: number
    /** The offset in milliseconds from the beginning of the audio stream to the end of the result. */
    EndTime: number
    /** `true` to indicate that Amazon Transcribe has additional transcription data to send, `false` to indicate that this is the last transcription result for the audio stream. */
    IsPartial: boolean
    /** A list of possible transcriptions for the audio. Each alternative typically contains one <code>item</code> that contains the result of the transcription. */
    Alternatives: Alternative[]
}

/** A list of possible transcriptions for the audio. */
export interface Alternative {
    /** The text that was transcribed from the audio. */
    Transcript: string
    /** One or more alternative interpretations of the input audio. */
    Items: Item[]
}

/** A word or phrase transcribed from the input audio. */
export interface Item {
    /** The offset from the beginning of the audio stream to the beginning of the audio that resulted in the item. */
    StartTime: number
    /** The offset from the beginning of the audio stream to the end of the audio that resulted in the item. */
    EndTime: string
    /**
     * The type of the item.  
     * `PRONUNCIATION` indicates that the item is a word that was recognized in the input audio.  
     * `PUNCTUATION` indicates that the item was interpreted as a pause in the input audio.
     */
    Type: 'PRONUNCIATION' | 'PUNCTUATION'
    /** The word or punctuation that was recognized in the input audio. */
    Content: string
}
