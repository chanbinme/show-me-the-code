package com.codestates.homework;

import com.codestates.member.controller.MemberController;
import com.codestates.member.dto.MemberDto;
import com.codestates.member.entity.Member;
import com.codestates.member.mapper.MemberMapper;
import com.codestates.member.service.MemberService;
import com.codestates.stamp.Stamp;
import com.google.gson.Gson;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.mapping.JpaMetamodelMappingContext;
import org.springframework.http.MediaType;
import org.springframework.restdocs.payload.JsonFieldType;
import org.springframework.restdocs.request.ParameterDescriptor;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.List;

import static com.codestates.util.ApiDocumentUtils.getRequestPreProcessor;
import static com.codestates.util.ApiDocumentUtils.getResponsePreProcessor;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doNothing;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.*;
import static org.springframework.restdocs.payload.PayloadDocumentation.*;
import static org.springframework.restdocs.request.RequestDocumentation.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(MemberController.class)
@MockBean(JpaMetamodelMappingContext.class)
@AutoConfigureRestDocs
public class MemberControllerDocumentationTest {
    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private MemberService memberService;

    @MockBean
    private MemberMapper mapper;

    @Autowired
    private Gson gson;

    @Test
    public void getMemberTest() throws Exception {
        // TODO 여기에 MemberController의 getMember() 핸들러 메서드 API 스펙 정보를 포함하는 테스트 케이스를 작성 하세요.
        // given
        long memberId = 1L;
        Member member = new Member("gksmfcksqls@gmail.com", "김찬빈", "010-2222-2222");
        member.setMemberId(memberId);
        member.setMemberStatus(Member.MemberStatus.MEMBER_ACTIVE);
        member.setStamp(new Stamp());

        MemberDto.response respons = new MemberDto.response(
                memberId,
                "gksmfcksqls@gmail.com",
                "김찬빈",
                "010-2222-2222",
                Member.MemberStatus.MEMBER_ACTIVE,
                new Stamp()
        );

        given(memberService.findMember(Mockito.anyLong())).willReturn(new Member());
        given(mapper.memberToMemberResponse(Mockito.any(Member.class))).willReturn(respons);
        // when
        ResultActions actions =
                mockMvc.perform(
                        get("/v11/members/{member-id}", memberId)
                                .accept(MediaType.APPLICATION_JSON)
                );
        // then
        actions
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.memberId").value(member.getMemberId()))
                .andExpect(jsonPath("$.data.name").value(member.getName()))
                .andExpect(jsonPath("$.data.phone").value(member.getPhone()))
                .andExpect(jsonPath("$.data.memberStatus").value(member.getMemberStatus().getStatus()))
                .andDo(document("get-member",
                        getRequestPreProcessor(),
                        getResponsePreProcessor(),
                        pathParameters(
                                parameterWithName("member-id").description("회원 식별자")
                        ),
                        responseFields(
                                List.of(
                                        fieldWithPath("data").type(JsonFieldType.OBJECT).description("결과 데이터"),
                                        fieldWithPath("data.memberId").type(JsonFieldType.NUMBER).description("회원 식별자"),
                                        fieldWithPath("data.email").type(JsonFieldType.STRING).description("이메일"),
                                        fieldWithPath("data.name").type(JsonFieldType.STRING).description("이름"),
                                        fieldWithPath("data.phone").type(JsonFieldType.STRING).description("휴대폰 번호"),
                                        fieldWithPath("data.memberStatus").type(JsonFieldType.STRING).description("회원 상태: 활동중 / 휴면 상태 / 탈퇴 상태"),
                                        fieldWithPath("data.stamp").type(JsonFieldType.NUMBER).description("스탬프 갯수")
                                )
                        )
                ));
    }

    @Test
    public void getMembersTest() throws Exception {
        // TODO 여기에 MemberController의 getMembers() 핸들러 메서드 API 스펙 정보를 포함하는 테스트 케이스를 작성 하세요.
        Member member1 = new Member("gksmfcksqls@gmail.com", "김찬빈", "010-2222-2222");
        member1.setMemberId(1L);
        member1.setMemberStatus(Member.MemberStatus.MEMBER_ACTIVE);
        member1.setStamp(new Stamp());

        Member member2 = new Member("jsjchb314@naver.com", "김현경", "010-1111-1111");
        member2.setMemberId(2L);
        member2.setMemberStatus(Member.MemberStatus.MEMBER_QUIT);
        member2.setStamp(new Stamp());

        MemberDto.response response1 = new MemberDto.response(
                1L,
                "gksmfcksqls@gmail.com",
                "김찬빈",
                "010-2222-2222",
                Member.MemberStatus.MEMBER_ACTIVE,
                new Stamp()
        );

        MemberDto.response response2 = new MemberDto.response(
                2L,
                "jsjchb314@naver.com",
                "김현경",
                "010-1111-1111",
                Member.MemberStatus.MEMBER_QUIT,
                new Stamp()
        );
        int page = 1;
        int size = 10;

        Page<Member> members = new PageImpl<>(List.of(member1, member2), PageRequest.of(page - 1, size, Sort.by("memberId").descending()), 2);
        List<MemberDto.response> responses = List.of(response1, response2);

        given(memberService.findMembers(Mockito.anyInt(), Mockito.anyInt())).willReturn(members);
        given(mapper.membersToMemberResponses(Mockito.anyList())).willReturn(responses);

        MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
        queryParams.add("page", String.valueOf(page));
        queryParams.add("size", String.valueOf(size));

        URI uri = UriComponentsBuilder.newInstance().path("/v11/members").build().toUri();

        // when
        ResultActions actions =
                mockMvc.perform(
                        get(uri)
                                .params(queryParams)
                                .accept(MediaType.APPLICATION_JSON)
                );

        // then
        actions
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[0].memberId").value(member1.getMemberId()))
                .andExpect(jsonPath("$.data[0].name").value(member1.getName()))
                .andExpect(jsonPath("$.data[0].phone").value(member1.getPhone()))
                .andExpect(jsonPath("$.data[0].memberStatus").value(member1.getMemberStatus().getStatus()))
                .andExpect(jsonPath("$.data[1].memberId").value(member2.getMemberId()))
                .andExpect(jsonPath("$.data[1].name").value(member2.getName()))
                .andExpect(jsonPath("$.data[1].phone").value(member2.getPhone()))
                .andExpect(jsonPath("$.data[1].memberStatus").value(member2.getMemberStatus().getStatus()))
                .andDo(
                        document("get-members",
                        getResponsePreProcessor(),
                        requestParameters(
                                List.of(
                                        parameterWithName("page").description("현재 페이지"),
                                        parameterWithName("size").description("한 페이지에 노출할 데이터 건수")
                                )
                        ),
                        responseFields(
                                List.of(
                                        fieldWithPath("data").type(JsonFieldType.ARRAY).description("결과 데이터"),
                                        fieldWithPath("data[*].memberId").type(JsonFieldType.NUMBER).description("회원 식별자"),
                                        fieldWithPath("data[*].email").type(JsonFieldType.STRING).description("이메일"),
                                        fieldWithPath("data[*].name").type(JsonFieldType.STRING).description("이름"),
                                        fieldWithPath("data[*].phone").type(JsonFieldType.STRING).description("휴대폰 번호"),
                                        fieldWithPath("data[*].memberStatus").type(JsonFieldType.STRING).description("회원 상태: 활동중 / 휴면 상태 / 탈퇴 상태"),
                                        fieldWithPath("data[*].stamp").type(JsonFieldType.NUMBER).description("스탬프 갯수"),
                                        fieldWithPath("pageInfo").type(JsonFieldType.OBJECT).description("페이지 정보"),
                                        fieldWithPath("pageInfo.page").type(JsonFieldType.NUMBER).description("현재 페이지"),
                                        fieldWithPath("pageInfo.size").type(JsonFieldType.NUMBER).description("한 페이지에 노출할 데이터 갯수"),
                                        fieldWithPath("pageInfo.totalElements").type(JsonFieldType.NUMBER).description("총 데이터 갯수"),
                                        fieldWithPath("pageInfo.totalPages").type(JsonFieldType.NUMBER).description("총 페이지 갯수")
                                )
                        )
                ));
    }

    @Test
    public void deleteMemberTest() throws Exception {
        // TODO 여기에 MemberController의 deleteMember() 핸들러 메서드 API 스펙 정보를 포함하는 테스트 케이스를 작성 하세요.
        // given
        long memberId = 1L;
        Member member = new Member("gksmfcksqls@gmail.com", "김찬빈", "010-2222-2222");
        member.setMemberId(memberId);
        member.setStamp(new Stamp());
        member.setMemberStatus(Member.MemberStatus.MEMBER_QUIT);

        // 반환 값이 void일 때 사용
        doNothing().when(memberService).deleteMember(member.getMemberId());

        // when
        ResultActions actions =
                mockMvc.perform(
                        delete("/v11/members/{member-id}", memberId)
                );

        // then
        actions
                .andExpect(status().isNoContent())
                .andDo(
                        document("delete-member",
                                getRequestPreProcessor()
                                , pathParameters(parameterWithName("member-id").description("회원 식별자"))));
    }
}
![](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/7d3ea8d8-4b7e-4efe-90c9-195366f148bb/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2022-11-13_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_2.20.45.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221115%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221115T142114Z&X-Amz-Expires=86400&X-Amz-Signature=34f2ba3cc05ca3a97339a4b0def741585d6ec79e371ecbec93a3acc2a1c298d9&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA%25202022-11-13%2520%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE%25202.20.45.png%22&x-id=GetObject)

![](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/351936d3-c23e-47ed-ad90-0f426740a3bb/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2022-11-13_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_2.21.11.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221115%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221115T142134Z&X-Amz-Expires=86400&X-Amz-Signature=7bda0b1f3151a673b3a71ef60a56c9a8c603d6a904884d75a89a45f73f006f32&X-Amz-SignedHeaders=host&response-content-disposition=filename%3D%22%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA%25202022-11-13%2520%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE%25202.21.11.png%22&x-id=GetObject)